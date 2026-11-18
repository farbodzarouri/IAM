package com.authprovider.service;

import com.authprovider.dto.SecurityPolicyRequest;
import com.authprovider.entity.AuthMode;
import com.authprovider.entity.SecurityPolicy;
import com.authprovider.exception.BadRequestException;
import com.authprovider.repository.SecurityPolicyRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Provides and updates the operational security policy in effect. Policies are persisted as
 * {@link SecurityPolicy} entities so that all cluster nodes share the same thresholds; the policy named
 * {@link SecurityPolicy#DEFAULT_NAME} is used. Without a repository (unit tests), an in-memory policy
 * holder is used.
 */
@Slf4j
@Service
public class SecurityPolicyService {

    private final SecurityPolicyRepository repository;
    private final SecurityPolicy inMemoryPolicy;
    private volatile boolean missingPolicyLogged;

    @Autowired
    public SecurityPolicyService(SecurityPolicyRepository repository) {
        this.repository = repository;
        this.inMemoryPolicy = SecurityPolicy.builder().name(SecurityPolicy.DEFAULT_NAME).build();
    }

    private SecurityPolicyService(SecurityPolicy inMemoryPolicy) {
        this.repository = null;
        this.inMemoryPolicy = inMemoryPolicy != null
                ? inMemoryPolicy
                : SecurityPolicy.builder().name(SecurityPolicy.DEFAULT_NAME).build();
    }

    /** Creates an in-memory policy provider backed by the given mutable {@link SecurityPolicy} instance. */
    public static SecurityPolicyService inMemory(SecurityPolicy policy) {
        return new SecurityPolicyService(policy);
    }

    /** Creates an in-memory policy provider with built-in defaults. */
    public static SecurityPolicyService withDefaults() {
        return new SecurityPolicyService(SecurityPolicy.builder().name(SecurityPolicy.DEFAULT_NAME).build());
    }

    /** Creates a policy provider returning defaults with the given MFA approval TTL. */
    public static SecurityPolicyService withMfaApprovalTtl(long ttlSeconds) {
        SecurityPolicy policy = SecurityPolicy.builder()
                .name(SecurityPolicy.DEFAULT_NAME)
                .mfaApprovalTtlSeconds(ttlSeconds)
                .build();
        return new SecurityPolicyService(policy);
    }

    public boolean isPersistent() {
        return repository != null;
    }

    /** @return the policy currently in effect (never {@code null}). */
    public SecurityPolicy current() {
        if (repository != null) {
            Optional<SecurityPolicy> stored;
            try {
                stored = repository.findByName(SecurityPolicy.DEFAULT_NAME);
            } catch (RuntimeException e) {
                log.error("Unable to load security policy; using built-in defaults", e);
                stored = Optional.empty();
            }
            if (stored.isPresent()) {
                SecurityPolicy policy = stored.get();
                if (isValid(policy)) {
                    return policy;
                }
                log.error("Stored security policy '{}' is invalid; using built-in defaults", policy.getName());
            } else if (!missingPolicyLogged) {
                missingPolicyLogged = true;
                log.warn("No '{}' security policy found; using built-in defaults", SecurityPolicy.DEFAULT_NAME);
            }
        }
        return isValid(inMemoryPolicy) ? inMemoryPolicy : SecurityPolicy.builder().name(SecurityPolicy.DEFAULT_NAME).build();
    }

    public SecurityPolicy updateCurrentPolicy(SecurityPolicyRequest req) {
        if (req == null) {
            throw new BadRequestException("Security policy payload is required");
        }
        String prompt = req.getChallengePrompt() == null ? "" : req.getChallengePrompt().trim();
        validatePolicyValues(
                req.getMaxFailures(),
                req.getLockoutSeconds(),
                req.getFailureWindowSeconds(),
                req.getChallengeTtlSeconds(),
                req.getChallengeMaxPending(),
                req.getMfaApprovalTtlSeconds(),
                req.getMfaMaxFailedAttempts(),
                req.getMfaLockoutWindowSeconds(),
                req.getOtpReuseWindowSeconds(),
                prompt);

        SecurityPolicy policy = repository != null
                ? repository.findByName(SecurityPolicy.DEFAULT_NAME)
                .orElseGet(() -> SecurityPolicy.builder().name(SecurityPolicy.DEFAULT_NAME).build())
                : inMemoryPolicy;

        policy.setMaxFailures(req.getMaxFailures());
        policy.setLockoutSeconds(req.getLockoutSeconds());
        policy.setFailureWindowSeconds(req.getFailureWindowSeconds());
        policy.setChallengeTtlSeconds(req.getChallengeTtlSeconds());
        policy.setChallengeMaxPending(req.getChallengeMaxPending());
        policy.setMfaApprovalTtlSeconds(req.getMfaApprovalTtlSeconds());
        policy.setMfaMaxFailedAttempts(req.getMfaMaxFailedAttempts());
        policy.setMfaLockoutWindowSeconds(req.getMfaLockoutWindowSeconds());
        policy.setOtpReuseWindowSeconds(req.getOtpReuseWindowSeconds());
        policy.setRequireMessageAuthenticator(req.isRequireMessageAuthenticator());
        policy.setStripRealm(req.isStripRealm());
        policy.setChallengePrompt(prompt);
        policy.setMfaOutOfBandEnabled(req.isMfaOutOfBandEnabled());
        policy.setDefaultAuthMode(req.getDefaultAuthMode() == null ? AuthMode.PASSWORD_AND_OTP : req.getDefaultAuthMode());

        return repository != null ? repository.saveAndFlush(policy) : policy;
    }

    public static boolean isValid(SecurityPolicy policy) {
        if (policy == null) {
            return false;
        }
        if (policy.getMaxFailures() <= 0 || policy.getLockoutSeconds() <= 0 || policy.getFailureWindowSeconds() <= 0) {
            return false;
        }
        if (policy.getChallengeTtlSeconds() <= 0 || policy.getChallengeMaxPending() <= 0) {
            return false;
        }
        if (policy.getMfaApprovalTtlSeconds() <= 0 || policy.getMfaMaxFailedAttempts() <= 0
                || policy.getMfaLockoutWindowSeconds() <= 0) {
            return false;
        }
        if (policy.getOtpReuseWindowSeconds() <= 0) {
            return false;
        }
        String prompt = policy.getChallengePrompt();
        return prompt != null && !prompt.isBlank() && prompt.getBytes(StandardCharsets.UTF_8).length <= 253;
    }

    private static void validatePolicyValues(int maxFailures, long lockoutSeconds, long failureWindowSeconds,
                                             long challengeTtlSeconds, int challengeMaxPending,
                                             long mfaApprovalTtlSeconds, int mfaMaxFailedAttempts,
                                             long mfaLockoutWindowSeconds, long otpReuseWindowSeconds,
                                             String challengePrompt) {
        if (maxFailures <= 0 || lockoutSeconds <= 0 || failureWindowSeconds <= 0) {
            throw new BadRequestException("Failure thresholds and windows must be positive");
        }
        if (challengeTtlSeconds <= 0 || challengeMaxPending <= 0) {
            throw new BadRequestException("Challenge TTL and max pending settings must be positive");
        }
        if (mfaApprovalTtlSeconds <= 0 || mfaMaxFailedAttempts <= 0 || mfaLockoutWindowSeconds <= 0) {
            throw new BadRequestException("MFA settings must be positive");
        }
        if (otpReuseWindowSeconds <= 0) {
            throw new BadRequestException("OTP reuse window must be positive");
        }
        if (challengePrompt.isBlank() || challengePrompt.getBytes(StandardCharsets.UTF_8).length > 253) {
            throw new BadRequestException("challengePrompt must be 1-253 UTF-8 bytes");
        }
    }
}
