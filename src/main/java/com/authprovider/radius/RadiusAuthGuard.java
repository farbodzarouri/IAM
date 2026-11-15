package com.authprovider.radius;

import com.authprovider.entity.AuthFailureRecord;
import com.authprovider.entity.SecurityPolicy;
import com.authprovider.service.AuthFailureStore;
import com.authprovider.service.InMemoryAuthFailureStore;
import com.authprovider.service.SecurityPolicyService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Brute-force protection for RADIUS authentication. Failure counters and lockouts are kept in an
 * {@link AuthFailureStore} (persistent and cluster-wide when running inside the application), and the
 * thresholds come from the persistent {@link SecurityPolicy}.
 */
@Slf4j
@Component
public class RadiusAuthGuard {

    static final Duration OTP_REUSE_WINDOW = Duration.ofSeconds(120);
    static final String SCOPE = AuthFailureRecord.SCOPE_RADIUS;

    private final Map<String, Instant> usedOtps = new ConcurrentHashMap<>();
    private final SecurityPolicyService policyService;
    private final AuthFailureStore failureStore;
    private final Clock clock;

    public RadiusAuthGuard(RadiusProperties properties, Clock clock) {
        this(SecurityPolicyService.fromProperties(properties), new InMemoryAuthFailureStore(), clock);
    }

    @Autowired
    public RadiusAuthGuard(SecurityPolicyService policyService, AuthFailureStore failureStore, Clock clock) {
        this.policyService = policyService;
        this.failureStore = failureStore;
        this.clock = clock;
    }

    public boolean isLocked(Long userId) {
        if (userId == null) {
            return false;
        }
        return failureStore.get(SCOPE, String.valueOf(userId))
                .map(state -> state.lockedUntil() != null && clock.instant().isBefore(state.lockedUntil()))
                .orElse(false);
    }

    public void recordFailure(Long userId) {
        if (userId == null) {
            return;
        }
        Instant now = clock.instant();
        SecurityPolicy policy = policyService.current();
        Duration window = Duration.ofSeconds(policy.getFailureWindowSeconds());
        Duration lockout = Duration.ofSeconds(policy.getLockoutSeconds());
        failureStore.update(SCOPE, String.valueOf(userId), current -> {
            int count = 1;
            Instant windowStart = now;
            if (current != null && now.isBefore(current.lastFailure().plus(window))
                    && (current.lockedUntil() == null || now.isBefore(current.lockedUntil()))) {
                count = current.count() + 1;
                windowStart = current.windowStart() != null ? current.windowStart() : now;
            }
            Instant lockedUntil = count >= policy.getMaxFailures() ? now.plus(lockout) : null;
            if (lockedUntil != null && (current == null || current.lockedUntil() == null)) {
                log.warn("RADIUS user id {} locked out for {}s after {} consecutive failures",
                        userId, lockout.getSeconds(), count);
            }
            return new AuthFailureStore.FailureState(count, windowStart, now, lockedUntil);
        }, true);
    }

    public void recordSuccess(Long userId) {
        if (userId == null) {
            return;
        }
        failureStore.delete(SCOPE, String.valueOf(userId));
    }

    public boolean markOtpUsed(Long userId, String otp) {
        Instant now = clock.instant();
        Instant expiry = now.plus(otpReuseWindow());
        String key = userId + ":" + otp;
        boolean[] fresh = {false};
        usedOtps.compute(key, (k, existing) -> {
            if (existing == null || !now.isBefore(existing)) {
                fresh[0] = true;
                return expiry;
            }
            return existing;
        });
        return fresh[0];
    }

    public void purgeExpired() {
        Instant now = clock.instant();
        SecurityPolicy policy = policyService.current();
        usedOtps.values().removeIf(expiry -> !now.isBefore(expiry));
        Duration window = Duration.ofSeconds(policy.getFailureWindowSeconds());
        failureStore.purgeExpired(SCOPE, now.minus(window), now);
    }

    private Duration otpReuseWindow() {
        long seconds = policyService.current().getOtpReuseWindowSeconds();
        return seconds > 0 ? Duration.ofSeconds(seconds) : OTP_REUSE_WINDOW;
    }
}
