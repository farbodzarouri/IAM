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
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Out-of-band MFA pre-authentication. Approvals ({@link MfaApproval}) and brute-force failure state
 * ({@link AuthFailureRecord}) are persisted so that approvals and lockouts survive restarts and are
 * honoured by every cluster node; thresholds come from the persistent {@link SecurityPolicy}.
 * OTP verification goes through the shared {@link OtpVerificationService}, so failures count towards the
 * account-wide lockout and accepted codes cannot be replayed on any other channel.
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

    private record PendingApproval(Long userId, Instant expiresAt) {
    }

    private final UserService userService;
    private final AccountResolver<User> accountResolver;
    private final Clock clock;
    private final SecurityPolicyService policyService;
    private final AuthFailureStore failureStore;
    private final MfaApprovalRepository approvalRepository;
    private final TransactionTemplate transactionTemplate;
    private final AuthAuditService auditService;
    private final OtpVerificationService otpVerifier;
    private final AccountLockoutService lockoutService;

    /** In-memory approvals (only used without a repository): normalized username -> approval. */
    private final Map<String, PendingApproval> approvals = new ConcurrentHashMap<>();
    private final Map<Long, String> knownFailureKeys = new ConcurrentHashMap<>();
    private volatile Instant lastPurge = Instant.EPOCH;

    public MfaPreAuthServiceImpl(UserService userService,
                                 TotpService totpService,
                                 Clock clock,
                                 long ttlSeconds) {
        this(userService, clock, validatedTtlPolicy(ttlSeconds), new InMemoryAuthFailureStore(),
                null, null, AuthAuditService.noOp(), OtpVerificationService.inMemory(totpService, null, clock));
    }

    @Autowired
    public MfaPreAuthServiceImpl(UserService userService,
                                 Clock clock,
                                 SecurityPolicyService policyService,
                                 AuthFailureStore failureStore,
                                 MfaApprovalRepository approvalRepository,
                                 PlatformTransactionManager transactionManager,
                                 AuthAuditService auditService,
                                 OtpVerificationService otpVerifier) {
        this.userService = userService;
        this.accountResolver = new AccountResolver<>(userService::findByUsernameIgnoreCase, null);
        this.clock = clock;
        this.policyService = policyService;
        this.failureStore = failureStore;
        this.approvalRepository = approvalRepository;
        this.transactionTemplate = transactionManager == null ? null : new TransactionTemplate(transactionManager);
        this.auditService = auditService == null ? AuthAuditService.noOp() : auditService;
        this.otpVerifier = otpVerifier;
        this.lockoutService = otpVerifier.lockoutService();
        this.lockoutService.addResetListener(this::clearFailures);
        if (approvalRepository == null) {
            // Node-local approvals must be discarded by this instance itself.
            lockoutService.sessionInvalidator().addListener(this::invalidateApprovals);
        }
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
        String normalized = UsernameNormalizer.normalize(username);
        if (normalized == null || otp == null || otp < 0) {
            audit(AuthAuditLog.Outcome.FAILURE, username, null, "INVALID_REQUEST");
            return false;
        }
        Instant now = clock.instant();
        SecurityPolicy policy = policyService.current();
        purgeIfDue(now, policy);

        AccountResolver.Resolution<User> resolution = accountResolver.resolve(username, true);
        User user = resolution.user();
        String key;
        if (user != null && user.getUsername() != null) {
            key = approvalKey(user);
            if (user.getId() != null) {
                knownFailureKeys.put(user.getId(), key);
            }
        } else {
            key = "unknown:" + username.trim().toLowerCase(java.util.Locale.ROOT);
        }

        Optional<Instant> mfaLockedUntil = lockedUntil(key, now, policy);
        if (mfaLockedUntil.isPresent()) {
            if (user != null && user.getId() != null) {
                lockoutService.lockUntil(user.getId(), mfaLockedUntil.get());
            }
            String auditKey = user == null ? normalized : key;
            Long auditUserId = user == null ? null : user.getId();
            log.warn("MFA pre-authentication rejected for locked-out user '{}'", auditKey);
            audit(AuthAuditLog.Outcome.LOCKED, auditKey, auditUserId, "LOCKED_OUT");
            return false;
        }

        if (user != null && (!user.isAccountEnabled() || isTokenLocked(user))) {
            log.warn("MFA pre-authentication rejected for disabled or token-locked account '{}'", user.getUsername());
            audit(AuthAuditLog.Outcome.LOCKED, key, user.getId(), "LOCKED_OUT");
            return false;
        }

        if (user == null || user.getSecret() == null || user.getSecret().isBlank() || user.getId() == null) {
            recordFailure(key, user == null ? null : user.getId(), now, policy);
            String auditKey = user == null ? normalized : key;
            audit(AuthAuditLog.Outcome.FAILURE, auditKey, user == null ? null : user.getId(),
                    user == null ? (resolution.status() == AccountResolver.Status.AMBIGUOUS ? "AMBIGUOUS_USER"
                            : "UNKNOWN_USER") : "NOT_ENROLLED");
            return false;
        }

        OtpVerificationService.Result result = otpVerifier.verifyTotp(user, otp);
        switch (result) {
            case ACCEPTED:
                break;
            case LOCKED:
                recordFailure(key, user.getId(), now, policy);
                log.warn("MFA pre-authentication rejected for locked-out account '{}'", user.getUsername());
                audit(AuthAuditLog.Outcome.LOCKED, key, user.getId(), "LOCKED_OUT");
                return false;
            case REPLAYED:
                recordFailure(key, user.getId(), now, policy);
                audit(AuthAuditLog.Outcome.FAILURE, key, user.getId(), "OTP_REPLAY");
                return false;
            case NOT_ENROLLED:
                recordFailure(key, user.getId(), now, policy);
                audit(AuthAuditLog.Outcome.FAILURE, key, user.getId(), "NOT_ENROLLED");
                return false;
            case INVALID:
            default:
                recordFailure(key, user.getId(), now, policy);
                audit(AuthAuditLog.Outcome.FAILURE, key, user.getId(), "INVALID_OTP");
                return false;
        }

        failureStore.delete(FAILURE_SCOPE, key);
        String approvalKey = approvalKey(user);
        Duration ttl = Duration.ofSeconds(policy.getMfaApprovalTtlSeconds());
        storeApproval(approvalKey, user.getId(), now, now.plus(ttl));
        log.info("MFA pre-authentication approved for user '{}' (valid {}s)", approvalKey, ttl.getSeconds());
        audit(AuthAuditLog.Outcome.SUCCESS, approvalKey, user.getId(), "APPROVED");
        return true;
    }

    @Override
    public boolean consumeApproval(String username) {
        return consume(username);
    }

    /**
     * Consumes the approval of the local account {@code userId} (the account the RADIUS identity resolved
     * to). Approvals of any other account are never touched, whatever user name the request carried.
     */
    @Override
    public boolean consumeApproval(String username, Long userId) {
        if (userId == null) {
            return false;
        }
        Instant now = clock.instant();
        if (isAccountOrTokenBlocked(userId, null)) {
            invalidateApprovals(userId);
            return false;
        }
        if (approvalRepository == null) {
            for (Map.Entry<String, PendingApproval> entry : approvals.entrySet()) {
                PendingApproval pending = entry.getValue();
                if (!userId.equals(pending.userId())) {
                    continue;
                }
                if (!now.isBefore(pending.expiresAt())) {
                    approvals.remove(entry.getKey(), pending);
                    continue;
                }
                if (approvals.remove(entry.getKey(), pending)) {
                    return true;
                }
            }
            return false;
        }
        for (MfaApproval approval : approvalRepository.findByUserId(userId)) {
            if (!now.isBefore(approval.getExpiresAt())) {
                approvalRepository.deleteByIdReturningCount(approval.getId());
                continue;
            }
            // Single use across the cluster: only the caller whose delete removed the row wins.
            if (approvalRepository.deleteByIdReturningCount(approval.getId()) == 1) {
                return true;
            }
        }
        return false;
    }

    /**
     * Consumes the approval stored under the normalized user name; an approval of a locked-out account is
     * discarded instead.
     */
    private boolean consume(String username) {
        String key = UsernameNormalizer.normalize(username);
        if (key == null) {
            return false;
        }
        Instant now = clock.instant();
        if (approvalRepository == null) {
            PendingApproval pending = approvals.get(key);
            if (pending == null) {
                return false;
            }
            if (!now.isBefore(pending.expiresAt())) {
                approvals.remove(key, pending);
                return false;
            }
            if (isAccountOrTokenBlocked(pending.userId(), null)) {
                approvals.remove(key, pending);
                return false;
            }
            // Single use: only the caller that removes this exact approval wins.
            return approvals.remove(key, pending);
        }
        Optional<MfaApproval> stored = approvalRepository.findByUsername(key);
        if (stored.isEmpty()) {
            return false;
        }
        MfaApproval approval = stored.get();
        if (!now.isBefore(approval.getExpiresAt())) {
            approvalRepository.deleteByIdReturningCount(approval.getId());
            return false;
        }
        if (isAccountOrTokenBlocked(approval.getUserId(), null)) {
            approvalRepository.deleteByIdReturningCount(approval.getId());
            return false;
        }
        // Single use across the cluster: only the caller whose delete removed the row wins.
        return approvalRepository.deleteByIdReturningCount(approval.getId()) == 1;
    }

    @Override
    public boolean hasActiveApproval(String username) {
        String key = UsernameNormalizer.normalize(username);
        if (key == null) {
            return false;
        }
        Instant now = clock.instant();
        Long userId;
        if (approvalRepository == null) {
            PendingApproval pending = approvals.get(key);
            if (pending == null || !now.isBefore(pending.expiresAt())) {
                return false;
            }
            userId = pending.userId();
        } else {
            Optional<MfaApproval> approval = approvalRepository.findByUsername(key);
            if (approval.isEmpty() || !now.isBefore(approval.get().getExpiresAt())) {
                return false;
            }
            userId = approval.get().getUserId();
        }
        return !isAccountOrTokenBlocked(userId, null);
    }

    private boolean isTokenLocked(User user) {
        return user != null && user.getOtpToken() != null && user.getOtpToken().getId() != null
                && lockoutService.isTokenLocked(user.getOtpToken().getId());
    }

    private boolean isAccountOrTokenBlocked(Long userId, User knownUser) {
        if (userId != null && lockoutService.isLocked(userId)) {
            return true;
        }
        User user = knownUser != null ? knownUser
                : (userService == null || userId == null ? null : userService.getUserById(userId));
        if (user != null) {
            return !user.isAccountEnabled() || isTokenLocked(user);
        }
        return false;
    }

    @Override
    public void invalidateApprovals(Long userId) {
        if (userId == null) {
            return;
        }
        if (approvalRepository == null) {
            approvals.values().removeIf(pending -> userId.equals(pending.userId()));
        } else {
            approvalRepository.deleteByUserId(userId);
        }
    }

    /**
     * Approvals are stored under the account's own (lower-cased) name, so accounts whose names only
     * differ by a realm suffix (e.g. {@code alice} and {@code alice@partner.example}) never share or
     * overwrite each other's approval.
     */
    private static String approvalKey(User user) {
        return user.getUsername().trim().toLowerCase(java.util.Locale.ROOT);
    }

    private void storeApproval(String key, Long userId, Instant now, Instant expiresAt) {
        if (approvalRepository == null) {
            approvals.values().removeIf(pending -> userId.equals(pending.userId()));
            approvals.put(key, new PendingApproval(userId, expiresAt));
            return;
        }
        RuntimeException last = null;
        for (int attempt = 0; attempt < 3; attempt++) {
            try {
                transactionTemplate.executeWithoutResult(status -> {
                    approvalRepository.deleteByUserId(userId);
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

    private Optional<Instant> lockedUntil(String key, Instant now, SecurityPolicy policy) {
        Duration window = Duration.ofSeconds(policy.getMfaLockoutWindowSeconds());
        return failureStore.get(FAILURE_SCOPE, key)
                .flatMap(w -> {
                    if (w.lockedUntil() != null) {
                        return now.isBefore(w.lockedUntil()) ? Optional.of(w.lockedUntil()) : Optional.empty();
                    }
                    if (w.count() >= policy.getMfaMaxFailedAttempts() && w.windowStart() != null
                            && now.isBefore(w.windowStart().plus(window))) {
                        return Optional.of(w.windowStart().plus(window));
                    }
                    return Optional.empty();
                });
    }

    private void recordFailure(String key, Long userId, Instant now, SecurityPolicy policy) {
        Duration window = Duration.ofSeconds(policy.getMfaLockoutWindowSeconds());
        boolean exists = failureStore.get(FAILURE_SCOPE, key).isPresent();
        if (!exists && failureStore.count(FAILURE_SCOPE) >= MAX_FAILURE_ENTRIES) {
            failureStore.purgeExpired(FAILURE_SCOPE, now.minus(window), now);
            if (failureStore.count(FAILURE_SCOPE) >= MAX_FAILURE_ENTRIES) {
                log.warn("Failure tracking capacity reached; dropping failure record for '{}'", key);
                return;
            }
        }
        Instant[] propagateUntil = {null};
        failureStore.update(FAILURE_SCOPE, key, w -> {
            if (w != null && w.lockedUntil() != null && now.isBefore(w.lockedUntil())) {
                int count = w.count() + 1;
                propagateUntil[0] = w.lockedUntil();
                return new AuthFailureStore.FailureState(count, w.windowStart(), now, w.lockedUntil());
            }
            if (w == null || (w.lockedUntil() != null && !now.isBefore(w.lockedUntil()))
                    || w.lastFailure() == null || !now.isBefore(w.lastFailure().plus(window))) {
                Instant until = 1 >= policy.getMfaMaxFailedAttempts() ? now.plus(window) : null;
                propagateUntil[0] = until;
                return new AuthFailureStore.FailureState(1, now, now, until);
            }
            int count = w.count() + 1;
            Instant until = count >= policy.getMfaMaxFailedAttempts() ? now.plus(window) : null;
            propagateUntil[0] = until;
            return new AuthFailureStore.FailureState(
                    count, w.windowStart() == null ? now : w.windowStart(), now, until);
        }, true);
        if (userId != null && propagateUntil[0] != null && now.isBefore(propagateUntil[0])) {
            lockoutService.lockUntil(userId, propagateUntil[0]);
        }
    }

    private void clearFailures(Long userId) {
        if (userId == null) {
            return;
        }
        String cached = knownFailureKeys.remove(userId);
        if (cached != null) {
            failureStore.delete(FAILURE_SCOPE, cached);
        }
        User user = userService == null ? null : userService.getUserById(userId);
        if (user != null && user.getUsername() != null) {
            failureStore.delete(FAILURE_SCOPE, approvalKey(user));
        }
    }

    private void purgeIfDue(Instant now, SecurityPolicy policy) {
        if (now.isBefore(lastPurge.plus(PURGE_INTERVAL))) {
            return;
        }
        lastPurge = now;
        if (approvalRepository == null) {
            approvals.entrySet().removeIf(e -> !now.isBefore(e.getValue().expiresAt()));
        } else {
            approvalRepository.deleteExpired(now);
        }
        Duration window = Duration.ofSeconds(policy.getMfaLockoutWindowSeconds());
        // Records are removed once their window started more than one window ago (window start <= last failure).
        failureStore.purgeExpired(FAILURE_SCOPE, now.minus(window), now);
    }

    private void audit(AuthAuditLog.Outcome outcome, String username, Long userId, String reason) {
        auditService.event(AuthAuditLog.Channel.MFA_PREAUTH, outcome)
                .username(username)
                .userId(userId)
                .reason(reason)
                .log();
    }
}
