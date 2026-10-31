package com.authprovider.radius;

import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class RadiusAuthGuard {

    static final Duration OTP_REUSE_WINDOW = Duration.ofSeconds(120);

    private final Map<Long, FailureState> failures = new ConcurrentHashMap<>();
    private final Map<String, Instant> usedOtps = new ConcurrentHashMap<>();
    private final RadiusProperties properties;
    private final Clock clock;

    public RadiusAuthGuard(RadiusProperties properties, Clock clock) {
        this.properties = properties;
        this.clock = clock;
    }

    private record FailureState(int count, Instant lastFailure, Instant lockedUntil) {
    }

    public boolean isLocked(Long userId) {
        FailureState state = failures.get(userId);
        return state != null && state.lockedUntil() != null && clock.instant().isBefore(state.lockedUntil());
    }

    public void recordFailure(Long userId) {
        Instant now = clock.instant();
        Duration lockout = Duration.ofSeconds(properties.getLockoutSeconds());
        failures.compute(userId, (id, current) -> {
            int count = 1;
            if (current != null && now.isBefore(current.lastFailure().plus(lockout))
                    && (current.lockedUntil() == null || now.isBefore(current.lockedUntil()))) {
                count = current.count() + 1;
            }
            Instant lockedUntil = count >= properties.getMaxFailures() ? now.plus(lockout) : null;
            return new FailureState(count, now, lockedUntil);
        });
    }

    public void recordSuccess(Long userId) {
        failures.remove(userId);
    }

    public boolean markOtpUsed(Long userId, String otp) {
        Instant now = clock.instant();
        Instant expiry = now.plus(OTP_REUSE_WINDOW);
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
        Duration lockout = Duration.ofSeconds(properties.getLockoutSeconds());
        usedOtps.values().removeIf(expiry -> !now.isBefore(expiry));
        failures.values().removeIf(state -> !now.isBefore(state.lastFailure().plus(lockout))
                && (state.lockedUntil() == null || !now.isBefore(state.lockedUntil())));
    }
}
