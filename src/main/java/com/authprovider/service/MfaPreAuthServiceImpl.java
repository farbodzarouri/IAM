package com.authprovider.service;

import com.authprovider.entity.AuthAuditLog;
import com.authprovider.entity.AuthFailureRecord;
import com.authprovider.entity.MfaApproval;
import com.authprovider.entity.SecurityPolicy;
import com.authprovider.entity.User;
import com.authprovider.repository.MfaApprovalRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Out-of-band MFA pre-authentication. Approvals ({@link MfaApproval}) and brute-force failure state
 * ({@link AuthFailureRecord}) are persisted so that approvals and lockouts survive restarts and are
 * honoured by every cluster node; thresholds come from the persistent {@link SecurityPolicy}.
 * When constructed without repositories (unit tests) the state is kept in memory.
 */
@Slf4j
@Service
public class MfaPreAuthServiceImpl implements MfaPreAuthService {

    static final int MAX_FAILED_ATTEMPTS = 5;
    static final Duration LOCKOUT_WINDOW = Duration.ofMinutes(15);
    private static final Duration PURGE_INTERVAL = Duration.ofSeconds(30);
    static final int MAX_FAILURE_ENTRIES = 10000;
    static final String FAILURE_SCOPE = AuthFailureRecord.SCOPE_MFA_PREAUTH;

    private final UserService userService;
    private final TotpService totpService;
    private final Clock clock;
    private final SecurityPolicyService policyService;
    private final AuthFailureStore failureStore;
    private final MfaApprovalRepository approvalRepository;
    private final TransactionTemplate transactionTemplate;
    private final AuthAuditService auditService;

    /** In-memory approvals (only used without a repository): normalized username -> approval expiry. */
    private final Map<String, Instant> approvals = new ConcurrentHashMap<>();
    /** user id -> last TOTP time step accepted (prevents OTP reuse). */
    private final Map<Long, Long> lastUsedTimeStep = new ConcurrentHashMap<>();
    private volatile Instant lastPurge = Instant.EPOCH;

    public MfaPreAuthServiceImpl(UserService userService,
                                 TotpService totpService,
                                 Clock clock,
                                 long ttlSeconds) {
        this(userService, totpService, clock, validatedTtlPolicy(ttlSeconds), new InMemoryAuthFailureStore(),
                null, null, AuthAuditService.noOp());
    }

    @Autowired
    public MfaPreAuthServiceImpl(UserService userService,
                                 TotpService totpService,
                                 Clock clock,
                                 SecurityPolicyService policyService,
                                 AuthFailureStore failureStore,
                                 MfaApprovalRepository approvalRepository,
                                 PlatformTransactionManager transactionManager,
                                 AuthAuditService auditService) {
        this.userService = userService;
        this.totpService = totpService;
        this.clock = clock;
        this.policyService = policyService;
        this.failureStore = failureStore;
        this.approvalRepository = approvalRepository;
        this.transactionTemplate = transactionManager == null ? null : new TransactionTemplate(transactionManager);
        this.auditService = auditService == null ? AuthAuditService.noOp() : auditService;
    }

    private static SecurityPolicyService validatedTtlPolicy(long ttlSeconds) {
        if (ttlSeconds <= 0) {
            throw new IllegalArgumentException("radius.mfa.ttl-seconds must be positive");
        }
        return SecurityPolicyService.withMfaApprovalTtl(ttlSeconds);
    }

    public Duration getApprovalTtl() {
        return Duration.ofSeconds(policyService.current().getMfaApprovalTtlSeconds());
    }

    @Override
    public boolean preAuthenticate(String username, Integer otp) {
        String key = UsernameNormalizer.normalize(username);
        if (key == null || otp == null || otp < 0) {
            audit(AuthAuditLog.Outcome.FAILURE, username, null, "INVALID_REQUEST");
            return false;
        }
        Instant now = clock.instant();
        SecurityPolicy policy = policyService.current();
        purgeIfDue(now, policy);

        if (isLockedOut(key, now, policy)) {
            log.warn("MFA pre-authentication rejected for locked-out user '{}'", key);
            audit(AuthAuditLog.Outcome.LOCKED, key, null, "LOCKED_OUT");
            return false;
        }

        User user = resolveUser(username, key);
        if (user == null || user.getSecret() == null || user.getId() == null) {
            recordFailure(key, now, policy);
            audit(AuthAuditLog.Outcome.FAILURE, key, user == null ? null : user.getId(),
                    user == null ? "UNKNOWN_USER" : "NOT_ENROLLED");
            return false;
        }

        OptionalLong step = totpService.findMatchingTimeStep(user.getSecret(), otp);
        if (step.isEmpty()) {
            recordFailure(key, now, policy);
            audit(AuthAuditLog.Outcome.FAILURE, key, user.getId(), "INVALID_OTP");
            return false;
        }
        if (!markTimeStepUsed(user.getId(), step.getAsLong())) {
            recordFailure(key, now, policy);
            audit(AuthAuditLog.Outcome.FAILURE, key, user.getId(), "OTP_REPLAY");
            return false;
        }

        failureStore.delete(FAILURE_SCOPE, key);
        String approvalKey = UsernameNormalizer.normalize(user.getUsername());
        Duration ttl = Duration.ofSeconds(policy.getMfaApprovalTtlSeconds());
        storeApproval(approvalKey, user.getId(), now, now.plus(ttl));
        log.info("MFA pre-authentication approved for user '{}' (valid {}s)", approvalKey, ttl.getSeconds());
        audit(AuthAuditLog.Outcome.SUCCESS, approvalKey, user.getId(), "APPROVED");
        return true;
    }

    @Override
    public boolean consumeApproval(String username) {
        String key = UsernameNormalizer.normalize(username);
        if (key == null) {
            return false;
        }
        Instant now = clock.instant();
        if (approvalRepository == null) {
            Instant expiry = approvals.remove(key);
            return expiry != null && now.isBefore(expiry);
        }
        Optional<MfaApproval> approval = approvalRepository.findByUsername(key);
        if (approval.isEmpty()) {
            return false;
        }
        // Single use across the cluster: only the caller whose delete removed the row wins.
        if (approvalRepository.deleteByIdReturningCount(approval.get().getId()) != 1) {
            return false;
        }
        return now.isBefore(approval.get().getExpiresAt());
    }

    @Override
    public boolean hasActiveApproval(String username) {
        String key = UsernameNormalizer.normalize(username);
        if (key == null) {
            return false;
        }
        Instant now = clock.instant();
        if (approvalRepository == null) {
            Instant expiry = approvals.get(key);
            return expiry != null && now.isBefore(expiry);
        }
        return approvalRepository.findByUsername(key)
                .map(approval -> now.isBefore(approval.getExpiresAt()))
                .orElse(false);
    }

    private void storeApproval(String key, Long userId, Instant now, Instant expiresAt) {
        if (approvalRepository == null) {
            approvals.put(key, expiresAt);
            return;
        }
        RuntimeException last = null;
        for (int attempt = 0; attempt < 3; attempt++) {
            try {
                transactionTemplate.executeWithoutResult(status -> {
                    approvalRepository.deleteByUsername(key);
                    approvalRepository.saveAndFlush(MfaApproval.builder()
                            .username(key)
                            .userId(userId)
                            .createdAt(now)
                            .expiresAt(expiresAt)
                            .build());
                });
                return;
            } catch (DataIntegrityViolationException e) {
                last = e;
            }
        }
        throw last;
    }

    private User resolveUser(String rawUsername, String normalized) {
        User user = uniqueMatch(rawUsername.trim());
        if (user == null && !normalized.equalsIgnoreCase(rawUsername.trim())) {
            user = uniqueMatch(normalized);
        }
        return user;
    }

    private User uniqueMatch(String username) {
        List<User> matches = userService.findByUsernameIgnoreCase(username);
        if (matches == null || matches.size() != 1) {
            if (matches != null && matches.size() > 1) {
                log.warn("Ambiguous username '{}' matches {} accounts; refusing MFA", username, matches.size());
            }
            return null;
        }
        return matches.get(0);
    }

    /** Atomically accepts the time step only if it is newer than any previously used one. */
    private boolean markTimeStepUsed(Long userId, long step) {
        boolean[] accepted = {false};
        lastUsedTimeStep.compute(userId, (id, previous) -> {
            if (previous == null || step > previous) {
                accepted[0] = true;
                return step;
            }
            return previous;
        });
        return accepted[0];
    }

    private boolean isLockedOut(String key, Instant now, SecurityPolicy policy) {
        Duration window = Duration.ofSeconds(policy.getMfaLockoutWindowSeconds());
        return failureStore.get(FAILURE_SCOPE, key)
                .map(w -> w.count() >= policy.getMfaMaxFailedAttempts() && now.isBefore(w.windowStart().plus(window)))
                .orElse(false);
    }

    private void recordFailure(String key, Instant now, SecurityPolicy policy) {
        Duration window = Duration.ofSeconds(policy.getMfaLockoutWindowSeconds());
        boolean exists = failureStore.get(FAILURE_SCOPE, key).isPresent();
        if (!exists && failureStore.count(FAILURE_SCOPE) >= MAX_FAILURE_ENTRIES) {
            failureStore.purgeExpired(FAILURE_SCOPE, now.minus(window), now);
            if (failureStore.count(FAILURE_SCOPE) >= MAX_FAILURE_ENTRIES) {
                log.warn("Failure tracking capacity reached; dropping failure record for '{}'", key);
                return;
            }
        }
        failureStore.update(FAILURE_SCOPE, key, w -> {
            if (w == null || !now.isBefore(w.windowStart().plus(window))) {
                return new AuthFailureStore.FailureState(1, now, now, null);
            }
            int count = w.count() + 1;
            Instant lockedUntil = count >= policy.getMfaMaxFailedAttempts() ? w.windowStart().plus(window) : null;
            return new AuthFailureStore.FailureState(count, w.windowStart(), now, lockedUntil);
        }, true);
    }

    private void purgeIfDue(Instant now, SecurityPolicy policy) {
        if (now.isBefore(lastPurge.plus(PURGE_INTERVAL))) {
            return;
        }
        lastPurge = now;
        if (approvalRepository == null) {
            approvals.entrySet().removeIf(e -> !now.isBefore(e.getValue()));
        } else {
            approvalRepository.deleteExpired(now);
        }
        Duration window = Duration.ofSeconds(policy.getMfaLockoutWindowSeconds());
        // Records are removed once their window started more than one window ago (window start <= last failure).
        failureStore.purgeExpired(FAILURE_SCOPE, now.minus(window), now);
        long currentStep = now.toEpochMilli() / 30000L;
        lastUsedTimeStep.entrySet().removeIf(e -> e.getValue() < currentStep - 2);
    }

    private void audit(AuthAuditLog.Outcome outcome, String username, Long userId, String reason) {
        auditService.event(AuthAuditLog.Channel.MFA_PREAUTH, outcome)
                .username(username)
                .userId(userId)
                .reason(reason)
                .log();
    }
}
