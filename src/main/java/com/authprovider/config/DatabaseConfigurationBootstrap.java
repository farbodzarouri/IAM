package com.authprovider.config;

import com.authprovider.dto.AdminRequest;
import com.authprovider.entity.LdapDirectory;
import com.authprovider.entity.RadiusClient;
import com.authprovider.entity.SecurityPolicy;
import com.authprovider.ldap.JndiLdapDirectoryAuthenticator;
import com.authprovider.ldap.LdapDirectoryService;
import com.authprovider.radius.CidrBlock;
import com.authprovider.repository.AdminRepository;
import com.authprovider.repository.LdapDirectoryRepository;
import com.authprovider.repository.RadiusClientRepository;
import com.authprovider.repository.SecurityPolicyRepository;
import com.authprovider.service.AdminService;
import com.authprovider.service.SecurityPolicyService;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
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
 * Seeds initial database records when tables are empty on first boot:
 * <ul>
 *     <li>{@code security_policies}: the built-in {@code default} policy (plus any optional
 *     {@code iam.bootstrap.policy.*} overrides);</li>
 *     <li>{@code radius_clients}: seeded only when {@code iam.bootstrap.radius.shared-secret} is
 *     supplied externally;</li>
 *     <li>{@code ldap_directories}: seeded only when {@code ldap.enabled=true} or {@code ldap.url} is
 *     configured;</li>
 *     <li>{@code admins}: seeded only when {@code iam.bootstrap.admin.username} and
 *     {@code iam.bootstrap.admin.password} are supplied externally.</li>
 * </ul>
 * Each table is only populated when empty, so runtime changes persisted in the database are never
 * overwritten.
 */
@Slf4j
@Component
public class DatabaseConfigurationBootstrap {

    static final String DEFAULT_CLIENT_NAME = "default";
    static final String DEFAULT_IPV6_CLIENT_NAME = "default-ipv6";
    static final String DEFAULT_DIRECTORY_NAME = "default";

    private final RadiusProperties radiusProperties;
    private final LdapProperties ldapProperties;
    private final BootstrapProperties bootstrapProperties;
    private final SecurityPolicyRepository policyRepository;
    private final RadiusClientRepository clientRepository;
    private final LdapDirectoryRepository directoryRepository;
    private final AdminService adminService;
    private final AdminRepository adminRepository;
    private final TransactionTemplate transactionTemplate;

    @Autowired
    public DatabaseConfigurationBootstrap(RadiusProperties radiusProperties,
                                          LdapProperties ldapProperties,
                                          BootstrapProperties bootstrapProperties,
                                          SecurityPolicyRepository policyRepository,
                                          RadiusClientRepository clientRepository,
                                          LdapDirectoryRepository directoryRepository,
                                          AdminService adminService,
                                          AdminRepository adminRepository,
                                          PlatformTransactionManager transactionManager) {
        this.radiusProperties = radiusProperties;
        this.ldapProperties = ldapProperties;
        this.bootstrapProperties = bootstrapProperties;
        this.policyRepository = policyRepository;
        this.clientRepository = clientRepository;
        this.directoryRepository = directoryRepository;
        this.adminService = adminService;
        this.adminRepository = adminRepository;
        this.transactionTemplate = new TransactionTemplate(transactionManager);
    }

    @PostConstruct
    public void seed() {
        if (bootstrapProperties == null || !bootstrapProperties.isSeedDefaults()) {
            log.info("Seeding of default configuration records is disabled (iam.bootstrap.seed-defaults=false)");
            return;
        }
        seedSecurityPolicy();
        seedRadiusClients();
        seedLdapDirectories();
        seedBootstrapAdmin();
    }

    void seedSecurityPolicy() {
        runSeed("security policy", () -> {
            if (policyRepository.findByName(SecurityPolicy.DEFAULT_NAME).isPresent()) {
                return;
            }
            SecurityPolicy policy = SecurityPolicy.builder().name(SecurityPolicy.DEFAULT_NAME).build();
            BootstrapProperties.Policy overrides = bootstrapProperties.getPolicy();
            if (overrides != null) {
                if (overrides.getMaxFailures() != null) {
                    policy.setMaxFailures(overrides.getMaxFailures());
                }
                if (overrides.getLockoutSeconds() != null) {
                    policy.setLockoutSeconds(overrides.getLockoutSeconds());
                    policy.setFailureWindowSeconds(overrides.getLockoutSeconds());
                }
                if (overrides.getChallengeTtlSeconds() != null) {
                    policy.setChallengeTtlSeconds(overrides.getChallengeTtlSeconds());
                }
                if (overrides.getMfaApprovalTtlSeconds() != null) {
                    policy.setMfaApprovalTtlSeconds(overrides.getMfaApprovalTtlSeconds());
                }
            }
            if (!SecurityPolicyService.isValid(policy)) {
                log.warn("Configured bootstrap security policy overrides are invalid; seeding built-in defaults");
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
            BootstrapProperties.Radius radiusSeed = bootstrapProperties.getRadius();
            String secret = radiusSeed == null ? null : radiusSeed.getSharedSecret();
            if (secret == null || secret.isEmpty()) {
                log.info("No iam.bootstrap.radius.shared-secret supplied; RADIUS clients are managed in the database");
                return;
            }
            Map<String, String> clients = resolveSeedClients(radiusSeed.getAllowedClients());
            List<RadiusClient> entities = new ArrayList<>();
            for (Map.Entry<String, String> client : clients.entrySet()) {
                entities.add(RadiusClient.builder()
                        .name(client.getKey())
                        .address(client.getValue())
                        .sharedSecret(secret)
                        .active(true)
                        .description("Seeded from iam.bootstrap.radius.*")
                        .build());
            }
            clientRepository.saveAllAndFlush(entities);
            log.info("Seeded {} RADIUS client(s) from bootstrap properties", entities.size());
        });
    }

    void seedLdapDirectories() {
        runSeed("LDAP directories", () -> {
            if (directoryRepository.count() > 0) {
                return;
            }
            boolean hasUrl = ldapProperties.getUrl() != null && !ldapProperties.getUrl().isBlank();
            if (!ldapProperties.isEnabled() && !hasUrl) {
                log.info("No bootstrap LDAP directory configured; LDAP directories are managed in the database");
                return;
            }
            if (ldapProperties.isEnabled()) {
                // Fail fast on an invalid directory configuration.
                new JndiLdapDirectoryAuthenticator(ldapProperties).validateConfiguration();
            }
            LdapDirectory directory = LdapDirectoryService.fromProperties(DEFAULT_DIRECTORY_NAME, ldapProperties);
            directoryRepository.saveAndFlush(directory);
            log.info("Seeded LDAP directory '{}' ({}, enabled={})", directory.getName(), directory.getUrl(),
                    directory.isEnabled());
        });
    }

    void seedBootstrapAdmin() {
        BootstrapProperties.Admin adminSeed = bootstrapProperties.getAdmin();
        if (adminSeed == null || !adminSeed.isEnabled()
                || adminService == null || adminRepository == null) {
            return;
        }
        String username = adminSeed.getUsername();
        String password = adminSeed.getPassword();
        if (username == null || username.isBlank() || password == null || password.isBlank()) {
            if (adminRepository.count() == 0) {
                log.info("No bootstrap admin credentials supplied (iam.bootstrap.admin.username/password); complete first-run /setup or configure in the database");
            }
            return;
        }
        runSeed("bootstrap admin", () -> {
            if (adminRepository.count() > 0) {
                return;
            }
            String trimmedUser = username.trim();
            if (adminRepository.findByUsername(trimmedUser).isPresent()) {
                return;
            }
            String displayName = adminSeed.getDisplayName() == null || adminSeed.getDisplayName().isBlank()
                    ? trimmedUser
                    : adminSeed.getDisplayName().trim();
            adminService.createAdmin(AdminRequest.builder()
                    .username(trimmedUser)
                    .password(password)
                    .displayName(displayName)
                    .enabled(true)
                    .build());
            log.info("Seeded bootstrap admin '{}'", trimmedUser);
        });
    }

    private Map<String, String> resolveSeedClients(List<String> rawAllowed) {
        Map<String, String> clients = new LinkedHashMap<>();
        List<String> allowed = rawAllowed == null ? List.of()
                : rawAllowed.stream().filter(c -> c != null && !c.isBlank()).map(String::trim).toList();
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
                    throw new IllegalStateException("Unable to resolve iam.bootstrap.radius.allowed-clients entry: " + entry, e);
                }
                log.warn("Unable to resolve iam.bootstrap.radius.allowed-clients entry '{}'; skipped", entry);
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
            log.info("Default {} already seeded by another node", what);
        }
    }
}
