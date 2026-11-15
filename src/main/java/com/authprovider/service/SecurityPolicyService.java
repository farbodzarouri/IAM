package com.authprovider.service;

import com.authprovider.entity.SecurityPolicy;
import com.authprovider.radius.RadiusProperties;
import com.authprovider.repository.SecurityPolicyRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 * Provides the operational security policy in effect. Policies are persisted as {@link SecurityPolicy}
 * entities so that all cluster nodes share the same thresholds; the policy named
 * {@link SecurityPolicy#DEFAULT_NAME} is used. Without a repository (unit tests / embedded use), or when
 * no policy row exists, a policy is derived from the {@code radius.*} configuration properties.
 */
@Slf4j
@Service
public class SecurityPolicyService {

    private final SecurityPolicyRepository repository;
    private final RadiusProperties properties;
    private volatile boolean missingPolicyLogged;

    @Autowired
    public SecurityPolicyService(SecurityPolicyRepository repository, RadiusProperties properties) {
        this.repository = repository;
        this.properties = properties;
    }

    /** Creates a policy provider backed solely by (mutable) configuration properties. */
    public static SecurityPolicyService fromProperties(RadiusProperties properties) {
        return new SecurityPolicyService(null, properties);
    }

    /** Creates a policy provider returning defaults with the given MFA approval TTL. */
    public static SecurityPolicyService withMfaApprovalTtl(long ttlSeconds) {
        RadiusProperties properties = new RadiusProperties();
        properties.getMfa().setTtlSeconds(ttlSeconds);
        return fromProperties(properties);
    }

    public boolean isPersistent() {
        return repository != null;
    }

    /** @return a detached copy of the policy currently in effect (never {@code null}). */
    public SecurityPolicy current() {
        if (repository != null) {
            Optional<SecurityPolicy> stored;
            try {
                stored = repository.findByName(SecurityPolicy.DEFAULT_NAME);
            } catch (RuntimeException e) {
                log.error("Unable to load security policy; using configured defaults", e);
                stored = Optional.empty();
            }
            if (stored.isPresent()) {
                SecurityPolicy policy = stored.get();
                try {
                    policy.validate();
                    return policy;
                } catch (IllegalStateException e) {
                    log.error("Stored security policy is invalid ({}); using configured defaults", e.getMessage());
                }
            } else if (!missingPolicyLogged) {
                missingPolicyLogged = true;
                log.warn("No '{}' security policy found; using configured defaults", SecurityPolicy.DEFAULT_NAME);
            }
        }
        return defaultsFromProperties(properties);
    }

    /** Builds a policy from the {@code radius.*} configuration properties. */
    public static SecurityPolicy defaultsFromProperties(RadiusProperties properties) {
        SecurityPolicy.SecurityPolicyBuilder builder = SecurityPolicy.builder().name(SecurityPolicy.DEFAULT_NAME);
        if (properties == null) {
            return builder.build();
        }
        builder.maxFailures(properties.getMaxFailures())
                .lockoutSeconds(properties.getLockoutSeconds())
                .failureWindowSeconds(properties.getLockoutSeconds());
        if (properties.getChallenge() != null) {
            builder.challengeTtlSeconds(properties.getChallenge().getTtlSeconds())
                    .challengeMaxPending(properties.getChallenge().getMaxPending());
        }
        if (properties.getMfa() != null) {
            builder.mfaApprovalTtlSeconds(properties.getMfa().getTtlSeconds());
        }
        return builder.build();
    }
}
