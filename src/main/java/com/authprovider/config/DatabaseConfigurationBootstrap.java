package com.authprovider.config;

import com.authprovider.entity.LdapDirectory;
import com.authprovider.entity.RadiusClient;
import com.authprovider.entity.SecurityPolicy;
import com.authprovider.ldap.JndiLdapDirectoryAuthenticator;
import com.authprovider.ldap.LdapDirectoryService;
import com.authprovider.radius.CidrBlock;
import com.authprovider.radius.RadiusProperties;
import com.authprovider.repository.LdapDirectoryRepository;
import com.authprovider.repository.RadiusClientRepository;
import com.authprovider.repository.SecurityPolicyRepository;
import com.authprovider.service.SecurityPolicyService;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Populates the runtime configuration tables from the legacy configuration properties when the
 * application starts against an uninitialized database:
 * <ul>
 *     <li>{@code security_policies}: the {@code default} policy from {@code radius.max-failures},
 *     {@code radius.lockout-seconds}, {@code radius.challenge.*} and {@code radius.mfa.ttl-seconds};</li>
 *     <li>{@code radius_clients}: one client per {@code radius.allowed-clients} entry (or a catch-all client
 *     when the list is empty) using {@code radius.shared-secret};</li>
 *     <li>{@code ldap_directories}: the directory described by the {@code ldap.*} properties.</li>
 * </ul>
 * Each table is only seeded while empty, so records managed at runtime are never overwritten. Concurrent
 * seeding by several cluster nodes is tolerated.
 */
@Slf4j
@Component
public class DatabaseConfigurationBootstrap {

    static final String DEFAULT_CLIENT_NAME = "default";
    static final String DEFAULT_IPV6_CLIENT_NAME = "default-ipv6";
    static final String DEFAULT_DIRECTORY_NAME = "default";

    private final RadiusProperties radiusProperties;
    private final LdapProperties ldapProperties;
    private final SecurityPolicyRepository policyRepository;
    private final RadiusClientRepository clientRepository;
    private final LdapDirectoryRepository directoryRepository;
    private final TransactionTemplate transactionTemplate;
    private final boolean enabled;

    public DatabaseConfigurationBootstrap(RadiusProperties radiusProperties,
                                          LdapProperties ldapProperties,
                                          SecurityPolicyRepository policyRepository,
                                          RadiusClientRepository clientRepository,
                                          LdapDirectoryRepository directoryRepository,
                                          PlatformTransactionManager transactionManager,
                                          @Value("${iam.bootstrap.seed-defaults:true}") boolean enabled) {
        this.radiusProperties = radiusProperties;
        this.ldapProperties = ldapProperties;
        this.policyRepository = policyRepository;
        this.clientRepository = clientRepository;
        this.directoryRepository = directoryRepository;
        this.transactionTemplate = new TransactionTemplate(transactionManager);
        this.enabled = enabled;
    }

    @PostConstruct
    public void seed() {
        if (!enabled) {
            log.info("Seeding of default configuration records is disabled (iam.bootstrap.seed-defaults=false)");
            return;
        }
        seedSecurityPolicy();
        seedRadiusClients();
        seedLdapDirectories();
    }

    void seedSecurityPolicy() {
        runSeed("security policy", () -> {
            if (policyRepository.findByName(SecurityPolicy.DEFAULT_NAME).isPresent()) {
                return;
            }
            SecurityPolicy policy = SecurityPolicyService.defaultsFromProperties(radiusProperties);
            try {
                policy.validate();
            } catch (IllegalStateException e) {
                log.warn("Configured security settings are invalid ({}); seeding built-in defaults", e.getMessage());
                policy = SecurityPolicy.builder().name(SecurityPolicy.DEFAULT_NAME).build();
            }
            policyRepository.saveAndFlush(policy);
            log.info("Seeded default security policy (max failures {}, lockout {}s, challenge TTL {}s, MFA approval TTL {}s)",
                    policy.getMaxFailures(), policy.getLockoutSeconds(), policy.getChallengeTtlSeconds(),
                    policy.getMfaApprovalTtlSeconds());
        });
    }

    void seedRadiusClients() {
        runSeed("RADIUS clients", () -> {
            if (clientRepository.count() > 0) {
                return;
            }
            String secret = radiusProperties.getSharedSecret();
            if (secret == null || secret.isEmpty()) {
                log.warn("radius.shared-secret is empty; no default RADIUS client seeded");
                return;
            }
            Map<String, String> clients = legacyClients();
            List<RadiusClient> entities = new ArrayList<>();
            for (Map.Entry<String, String> client : clients.entrySet()) {
                entities.add(RadiusClient.builder()
                        .name(client.getKey())
                        .address(client.getValue())
                        .sharedSecret(secret)
                        .active(true)
                        .description("Seeded from radius.shared-secret / radius.allowed-clients")
                        .build());
            }
            clientRepository.saveAllAndFlush(entities);
            log.info("Seeded {} RADIUS client(s) from configuration properties", entities.size());
        });
    }

    void seedLdapDirectories() {
        runSeed("LDAP directories", () -> {
            if (directoryRepository.count() > 0) {
                return;
            }
            if (ldapProperties.isEnabled()) {
                // Fail fast on an invalid directory configuration, as before.
                new JndiLdapDirectoryAuthenticator(ldapProperties).validateConfiguration();
            }
            LdapDirectory directory = LdapDirectoryService.fromProperties(DEFAULT_DIRECTORY_NAME, ldapProperties);
            directoryRepository.saveAndFlush(directory);
            log.info("Seeded LDAP directory '{}' ({}, enabled={})", directory.getName(), directory.getUrl(),
                    directory.isEnabled());
        });
    }

    /** name -> address (IP or CIDR) for the legacy single-secret client configuration. */
    private Map<String, String> legacyClients() {
        Map<String, String> clients = new LinkedHashMap<>();
        List<String> allowed = radiusProperties.getAllowedClients() == null ? List.of()
                : radiusProperties.getAllowedClients().stream().filter(c -> c != null && !c.isBlank()).map(String::trim).toList();
        if (allowed.isEmpty()) {
            clients.put(DEFAULT_CLIENT_NAME, "0.0.0.0/0");
            clients.put(DEFAULT_IPV6_CLIENT_NAME, "::/0");
            return clients;
        }
        for (String entry : allowed) {
            if (CidrBlock.isValid(entry)) {
                clients.putIfAbsent(uniqueName(clients, entry), entry);
                continue;
            }
            try {
                for (InetAddress address : InetAddress.getAllByName(entry)) {
                    String ip = address.getHostAddress();
                    int scope = ip.indexOf('%');
                    if (scope >= 0) {
                        ip = ip.substring(0, scope);
                    }
                    if (!clients.containsValue(ip)) {
                        clients.put(uniqueName(clients, entry), ip);
                    }
                }
            } catch (UnknownHostException e) {
                if (radiusProperties.isEnabled()) {
                    throw new IllegalStateException("Unable to resolve radius.allowed-clients entry: " + entry, e);
                }
                log.warn("Unable to resolve radius.allowed-clients entry '{}'; skipped", entry);
            }
        }
        return clients;
    }

    private static String uniqueName(Map<String, String> clients, String base) {
        String name = base.length() > 120 ? base.substring(0, 120) : base;
        String candidate = name;
        int suffix = 2;
        while (clients.containsKey(candidate)) {
            candidate = name + "-" + suffix++;
        }
        return candidate;
    }

    private void runSeed(String what, Runnable seed) {
        try {
            transactionTemplate.executeWithoutResult(status -> seed.run());
        } catch (DataIntegrityViolationException e) {
            // Another node seeded the same table concurrently.
            log.info("Default {} already seeded by another node", what);
        }
    }
}
