package com.authprovider.service;

import com.authprovider.entity.AuthFailureRecord;
import com.authprovider.entity.SecurityPolicy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.LongConsumer;

/**
 * Single, channel-independent brute-force protection for local accounts. Every authentication channel
 * (web login, out-of-band MFA pre-authentication, direct OTP / OCRA validation, in-band and out-of-band
 * RADIUS) records its failures against the same per-account record, so that reaching the threshold on any
 * channel blocks the account everywhere. State lives in the {@link AuthFailureStore} (database backed and
 * therefore shared by all cluster nodes) and thresholds come from the persistent {@link SecurityPolicy}
 * ({@code maxFailures}, {@code lockoutSeconds}, {@code failureWindowSeconds}).
 *
 * <p>Second-factor checks use a reservation protocol ({@link #tryBeginAttempt} followed by
 * {@link #confirmFailure} or {@link #recordSuccess}) that counts an attempt <em>before</em> the code is
 * verified. This bounds the number of guesses even when many requests are processed concurrently on
 * several nodes: once the in-flight and failed attempts reach the threshold, further attempts are refused.
 */
@Slf4j
@Service
public class AccountLockoutService {

    /** Records are keyed by user id. The scope name is kept for compatibility with existing data. */
    public static final String SCOPE = AuthFailureRecord.SCOPE_ACCOUNT;
    public static final String SCOPE_ADMIN = AuthFailureRecord.SCOPE_ADMIN;
    public static final String SCOPE_OTP_TOKEN = AuthFailureRecord.SCOPE_OTP_TOKEN;
    public static final String SCOPE_OAUTH_CLIENT = AuthFailureRecord.SCOPE_OAUTH_CLIENT;

    private final SecurityPolicyService policyService;
    private final AuthFailureStore failureStore;
    private final Clock clock;
    private final PendingAuthSessionInvalidator sessionInvalidator;
    private final List<LongConsumer> resetListeners = new CopyOnWriteArrayList<>();
    private final List<LongConsumer> tokenLockListeners = new CopyOnWriteArrayList<>();

    @Autowired
    public AccountLockoutService(SecurityPolicyService policyService, AuthFailureStore failureStore, Clock clock,
                                 PendingAuthSessionInvalidator sessionInvalidator) {
        this.policyService = policyService == null ? SecurityPolicyService.withDefaults() : policyService;
        this.failureStore = failureStore == null ? new InMemoryAuthFailureStore() : failureStore;
        this.clock = clock == null ? Clock.systemUTC() : clock;
        this.sessionInvalidator = sessionInvalidator == null ? new PendingAuthSessionInvalidator() : sessionInvalidator;
    }

    public AccountLockoutService(SecurityPolicyService policyService, AuthFailureStore failureStore, Clock clock) {
        this(policyService, failureStore, clock, null);
    }

    /** Node-local lockout tracking with default thresholds (unit tests / embedded use). */
    public static AccountLockoutService inMemory(Clock clock) {
        return new AccountLockoutService(null, new InMemoryAuthFailureStore(), clock, null);
    }

    public PendingAuthSessionInvalidator sessionInvalidator() {
        return sessionInvalidator;
    }

    public SecurityPolicyService policyService() {
        return policyService;
    }

    public AuthFailureStore failureStore() {
        return failureStore;
    }

    public Clock clock() {
        return clock;
    }

    /** Invalidates all pending authentication sessions (RADIUS challenges, MFA approvals) of the account. */
    public void invalidatePendingSessions(Long userId) {
        sessionInvalidator.invalidate(userId);
    }

    public boolean isLocked(Long userId) {
        return userId != null && isLocked(SCOPE, key(userId));
    }

    public boolean isAdminLocked(Long adminId) {
        return adminId != null && isLocked(SCOPE_ADMIN, key(adminId));
    }

    public boolean isTokenLocked(Long tokenId) {
        return tokenId != null && isLocked(SCOPE_OTP_TOKEN, key(tokenId));
    }

    /** Whether OAuth 2.0 client authentication of the given {@code clients.id} is locked out. */
    public boolean isClientLocked(Long clientId) {
        return clientId != null && isLocked(SCOPE_OAUTH_CLIENT, key(clientId));
    }

    /** Lockout expiry of an OAuth 2.0 client, if currently locked out by a lockout period. */
    public Optional<Instant> clientLockedUntil(Long clientId) {
        if (clientId == null) {
            return Optional.empty();
        }
        Instant now = clock.instant();
        return failureStore.get(SCOPE_OAUTH_CLIENT, key(clientId))
                .map(AuthFailureStore.FailureState::lockedUntil)
                .filter(now::isBefore);
    }

    /**
     * Atomically reserves one authentication attempt. Returns {@code false} (without changing state) if
     * the account is locked or the threshold is already exhausted by failed / in-flight attempts. A
     * reservation must be followed by {@link #confirmFailure} or {@link #recordSuccess}.
     */
    public boolean tryBeginAttempt(Long userId) {
        return userId == null || tryBeginAttempt(SCOPE, key(userId));
    }

    public boolean tryBeginAdminAttempt(Long adminId) {
        return adminId == null || tryBeginAttempt(SCOPE_ADMIN, key(adminId));
    }

    public boolean tryBeginTokenAttempt(Long tokenId) {
        return tokenId == null || tryBeginAttempt(SCOPE_OTP_TOKEN, key(tokenId));
    }

    /**
     * Reserves one OAuth 2.0 client secret verification (see {@link #tryBeginAttempt(Long)}); must be
     * followed by {@link #confirmClientFailure} or {@link #recordClientSuccess}.
     */
    public boolean tryBeginClientAttempt(Long clientId) {
        return clientId != null && tryBeginAttempt(SCOPE_OAUTH_CLIENT, key(clientId));
    }

    /** Confirms a reserved client authentication failure; returns {@code true} if the client became locked. */
    public boolean confirmClientFailure(Long clientId) {
        if (clientId == null) {
            return false;
        }
        boolean[] locked = {false};
        applyFailure(SCOPE_OAUTH_CLIENT, key(clientId), false, () -> locked[0] = true);
        return locked[0];
    }

    public void recordClientSuccess(Long clientId) {
        if (clientId != null) {
            failureStore.delete(SCOPE_OAUTH_CLIENT, key(clientId));
        }
    }

    /** Administrative unblock: clears failure counters and any active lockout of the client. */
    public void clearClientLockout(Long clientId) {
        recordClientSuccess(clientId);
    }

    /** Confirms that a reserved attempt failed, locking the account when the threshold is reached. */
    public void confirmFailure(Long userId) {
        if (userId != null) {
            applyFailure(SCOPE, key(userId), false, () -> invalidateOnLock(userId));
        }
    }

    /** Records a failed attempt that was not reserved beforehand (e.g. a wrong primary password). */
    public void recordFailure(Long userId) {
        if (userId != null) {
            applyFailure(SCOPE, key(userId), true, () -> invalidateOnLock(userId));
        }
    }

    public void confirmAdminFailure(Long adminId, Long otpTokenId) {
        if (adminId != null) {
            applyFailure(SCOPE_ADMIN, key(adminId), false, () -> {
                if (otpTokenId != null) {
                    lockToken(otpTokenId);
                }
            });
        }
    }

    public void recordAdminFailure(Long adminId, Long otpTokenId) {
        if (adminId != null) {
            applyFailure(SCOPE_ADMIN, key(adminId), true, () -> {
                if (otpTokenId != null) {
                    lockToken(otpTokenId);
                }
            });
        }
    }

    public void confirmTokenFailure(Long tokenId) {
        if (tokenId != null) {
            applyFailure(SCOPE_OTP_TOKEN, key(tokenId), false, () -> notifyTokenLocked(tokenId));
        }
    }

    public void recordTokenFailure(Long tokenId) {
        if (tokenId != null) {
            applyFailure(SCOPE_OTP_TOKEN, key(tokenId), true, () -> notifyTokenLocked(tokenId));
        }
    }

    public void addResetListener(LongConsumer listener) {
        if (listener != null) {
            resetListeners.add(listener);
        }
    }

    public void addTokenLockListener(LongConsumer listener) {
        if (listener != null) {
            tokenLockListeners.add(listener);
        }
    }

    /** A successful authentication clears the failure counter and any lockout of the account. */
    public void recordSuccess(Long userId) {
        if (userId == null) {
            return;
        }
        failureStore.delete(SCOPE, key(userId));
        for (LongConsumer listener : resetListeners) {
            try {
                listener.accept(userId);
            } catch (RuntimeException e) {
                log.error("Failed to notify reset listener for account id {}", userId, e);
            }
        }
    }

    public void recordAdminSuccess(Long adminId) {
        if (adminId != null) {
            failureStore.delete(SCOPE_ADMIN, key(adminId));
        }
    }

    public void recordTokenSuccess(Long tokenId) {
        if (tokenId != null && !isTokenLocked(tokenId)) {
            failureStore.delete(SCOPE_OTP_TOKEN, key(tokenId));
        }
    }

    public void lockToken(Long tokenId) {
        if (tokenId == null) {
            return;
        }
        Instant until = clock.instant().plus(Duration.ofSeconds(policyService.current().getLockoutSeconds()));
        if (lockScopeUntil(SCOPE_OTP_TOKEN, key(tokenId), until)) {
            log.warn("OTP token id {} locked out until {}", tokenId, until);
            notifyTokenLocked(tokenId);
        }
    }

    /** Enforces an account-wide lockout until at least {@code until} (e.g. triggered by MFA pre-auth). */
    public void lockUntil(Long userId, Instant until) {
        if (userId == null || until == null) {
            return;
        }
        if (lockScopeUntil(SCOPE, key(userId), until)) {
            log.warn("Account id {} locked out across all channels until {}", userId, until);
            invalidateOnLock(userId);
        }
    }

    public void purgeExpired() {
        Instant now = clock.instant();
        SecurityPolicy policy = policyService.current();
        Duration window = Duration.ofSeconds(policy.getFailureWindowSeconds());
        Instant cutoff = now.minus(window);
        failureStore.purgeExpired(SCOPE, cutoff, now);
        failureStore.purgeExpired(SCOPE_ADMIN, cutoff, now);
        failureStore.purgeExpired(SCOPE_OTP_TOKEN, cutoff, now);
        failureStore.purgeExpired(SCOPE_OAUTH_CLIENT, cutoff, now);
    }

    private boolean isLocked(String scope, String subjectKey) {
        Instant now = clock.instant();
        SecurityPolicy policy = policyService.current();
        return failureStore.get(scope, subjectKey).map(state -> isLocked(state, now, policy)).orElse(false);
    }

    private boolean tryBeginAttempt(String scope, String subjectKey) {
        Instant now = clock.instant();
        SecurityPolicy policy = policyService.current();
        Duration window = Duration.ofSeconds(policy.getFailureWindowSeconds());
        boolean[] reserved = {false};
        failureStore.update(scope, subjectKey, current -> {
            reserved[0] = false;
            if (current != null && isLocked(current, now, policy)) {
                return current;
            }
            reserved[0] = true;
            if (isFresh(current, now, window)) {
                return new AuthFailureStore.FailureState(1, now, now, null);
            }
            return new AuthFailureStore.FailureState(current.count() + 1,
                    current.windowStart() == null ? now : current.windowStart(), now, null);
        }, true);
        return reserved[0];
    }

    private boolean lockScopeUntil(String scope, String subjectKey, Instant until) {
        Instant now = clock.instant();
        if (!now.isBefore(until)) {
            return false;
        }
        SecurityPolicy policy = policyService.current();
        boolean[] newlyLocked = {false};
        failureStore.update(scope, subjectKey, current -> {
            boolean alreadyLocked = current != null && isLocked(current, now, policy);
            newlyLocked[0] = !alreadyLocked;
            int count = current == null ? policy.getMaxFailures() : Math.max(current.count(), 1);
            Instant windowStart = current != null && current.windowStart() != null ? current.windowStart() : now;
            Instant effectiveUntil = (current != null && current.lockedUntil() != null
                    && current.lockedUntil().isAfter(until))
                    ? current.lockedUntil()
                    : until;
            return new AuthFailureStore.FailureState(count, windowStart, now, effectiveUntil);
        }, true);
        return newlyLocked[0];
    }

    private void applyFailure(String scope, String subjectKey, boolean increment, Runnable onNewlyLocked) {
        Instant now = clock.instant();
        SecurityPolicy policy = policyService.current();
        Duration window = Duration.ofSeconds(policy.getFailureWindowSeconds());
        Duration lockout = Duration.ofSeconds(policy.getLockoutSeconds());
        boolean[] newlyLocked = {false};
        int[] failures = {0};
        failureStore.update(scope, subjectKey, current -> {
            newlyLocked[0] = false;
            if (current != null && current.lockedUntil() != null && now.isBefore(current.lockedUntil())) {
                // Already locked: keep the lockout as is.
                return new AuthFailureStore.FailureState(current.count(), current.windowStart(), now,
                        current.lockedUntil());
            }
            int count;
            Instant windowStart;
            if (isFresh(current, now, window)) {
                count = 1;
                windowStart = now;
            } else {
                count = increment ? current.count() + 1 : Math.max(1, current.count());
                windowStart = current.windowStart() == null ? now : current.windowStart();
            }
            Instant lockedUntil = null;
            if (count >= policy.getMaxFailures()) {
                lockedUntil = now.plus(lockout);
                newlyLocked[0] = true;
            }
            failures[0] = count;
            return new AuthFailureStore.FailureState(count, windowStart, now, lockedUntil);
        }, true);
        if (newlyLocked[0]) {
            log.warn("{} '{}' locked out for {}s after {} consecutive authentication failures",
                    scope, subjectKey, lockout.getSeconds(), failures[0]);
            if (onNewlyLocked != null) {
                onNewlyLocked.run();
            }
        }
    }

    private void invalidateOnLock(Long userId) {
        try {
            sessionInvalidator.invalidate(userId);
        } catch (RuntimeException e) {
            log.error("Failed to invalidate pending sessions of locked-out account id {}", userId, e);
        }
    }

    private void notifyTokenLocked(Long tokenId) {
        for (LongConsumer listener : tokenLockListeners) {
            try {
                listener.accept(tokenId);
            } catch (RuntimeException e) {
                log.error("Failed to notify token lock listener for token id {}", tokenId, e);
            }
        }
    }

    /** True when no counting window is active (no record, window elapsed, or a previous lockout expired). */
    private static boolean isFresh(AuthFailureStore.FailureState current, Instant now, Duration window) {
        if (current == null) {
            return true;
        }
        if (current.lockedUntil() != null) {
            return !now.isBefore(current.lockedUntil());
        }
        return current.lastFailure() == null || !now.isBefore(current.lastFailure().plus(window));
    }

    private static boolean isLocked(AuthFailureStore.FailureState state, Instant now, SecurityPolicy policy) {
        if (state.lockedUntil() != null) {
            return now.isBefore(state.lockedUntil());
        }
        // Failed plus in-flight (reserved) attempts already exhaust the threshold within the window.
        Duration window = Duration.ofSeconds(policy.getFailureWindowSeconds());
        return state.count() >= policy.getMaxFailures()
                && state.lastFailure() != null && now.isBefore(state.lastFailure().plus(window));
    }

    private static String key(Long userId) {
        return String.valueOf(userId);
    }
}
