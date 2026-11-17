package com.authprovider.service;

import com.authprovider.entity.AuthFailureRecord;
import com.authprovider.entity.SecurityPolicy;
import com.authprovider.radius.RadiusProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
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

    private final SecurityPolicyService policyService;
    private final AuthFailureStore failureStore;
    private final Clock clock;
    private final PendingAuthSessionInvalidator sessionInvalidator;
    private final List<LongConsumer> resetListeners = new CopyOnWriteArrayList<>();

    @Autowired
    public AccountLockoutService(SecurityPolicyService policyService, AuthFailureStore failureStore, Clock clock,
                                 PendingAuthSessionInvalidator sessionInvalidator) {
        this.policyService = policyService == null ? SecurityPolicyService.fromProperties(new RadiusProperties())
                : policyService;
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
        if (userId == null) {
            return false;
        }
        Instant now = clock.instant();
        SecurityPolicy policy = policyService.current();
        return failureStore.get(SCOPE, key(userId)).map(state -> isLocked(state, now, policy)).orElse(false);
    }

    /**
     * Atomically reserves one authentication attempt. Returns {@code false} (without changing state) if
     * the account is locked or the threshold is already exhausted by failed / in-flight attempts. A
     * reservation must be followed by {@link #confirmFailure} or {@link #recordSuccess}.
     */
    public boolean tryBeginAttempt(Long userId) {
        if (userId == null) {
            return true;
        }
        Instant now = clock.instant();
        SecurityPolicy policy = policyService.current();
        Duration window = Duration.ofSeconds(policy.getFailureWindowSeconds());
        boolean[] reserved = {false};
        failureStore.update(SCOPE, key(userId), current -> {
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

    /** Confirms that a reserved attempt failed, locking the account when the threshold is reached. */
    public void confirmFailure(Long userId) {
        applyFailure(userId, false);
    }

    /** Records a failed attempt that was not reserved beforehand (e.g. a wrong primary password). */
    public void recordFailure(Long userId) {
        applyFailure(userId, true);
    }

    public void addResetListener(LongConsumer listener) {
        if (listener != null) {
            resetListeners.add(listener);
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

    /** Enforces an account-wide lockout until at least {@code until} (e.g. triggered by MFA pre-auth). */
    public void lockUntil(Long userId, Instant until) {
        if (userId == null || until == null) {
            return;
        }
        Instant now = clock.instant();
        if (!now.isBefore(until)) {
            return;
        }
        SecurityPolicy policy = policyService.current();
        boolean[] newlyLocked = {false};
        failureStore.update(SCOPE, key(userId), current -> {
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
        if (newlyLocked[0]) {
            log.warn("Account id {} locked out across all channels until {}", userId, until);
            try {
                sessionInvalidator.invalidate(userId);
            } catch (RuntimeException e) {
                log.error("Failed to invalidate pending sessions of locked-out account id {}", userId, e);
            }
        }
    }

    public void purgeExpired() {
        Instant now = clock.instant();
        SecurityPolicy policy = policyService.current();
        Duration window = Duration.ofSeconds(policy.getFailureWindowSeconds());
        failureStore.purgeExpired(SCOPE, now.minus(window), now);
    }

    private void applyFailure(Long userId, boolean increment) {
        if (userId == null) {
            return;
        }
        Instant now = clock.instant();
        SecurityPolicy policy = policyService.current();
        Duration window = Duration.ofSeconds(policy.getFailureWindowSeconds());
        Duration lockout = Duration.ofSeconds(policy.getLockoutSeconds());
        boolean[] newlyLocked = {false};
        int[] failures = {0};
        failureStore.update(SCOPE, key(userId), current -> {
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
            log.warn("Account id {} locked out for {}s after {} consecutive authentication failures",
                    userId, lockout.getSeconds(), failures[0]);
            try {
                sessionInvalidator.invalidate(userId);
            } catch (RuntimeException e) {
                log.error("Failed to invalidate pending sessions of locked-out account id {}", userId, e);
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
