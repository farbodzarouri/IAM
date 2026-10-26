package com.authprovider.service;

import com.authprovider.entity.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.OptionalLong;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Service
public class MfaPreAuthServiceImpl implements MfaPreAuthService {

    static final int MAX_FAILED_ATTEMPTS = 5;
    static final Duration LOCKOUT_WINDOW = Duration.ofMinutes(15);
    private static final Duration PURGE_INTERVAL = Duration.ofSeconds(30);

    private final UserService userService;
    private final TotpService totpService;
    private final Clock clock;
    private final Duration approvalTtl;

    /** normalized username -> approval expiry. */
    private final Map<String, Instant> approvals = new ConcurrentHashMap<>();
    /** user id -> last TOTP time step accepted (prevents OTP reuse). */
    private final Map<Long, Long> lastUsedTimeStep = new ConcurrentHashMap<>();
    /** normalized username -> failure tracking (brute-force protection). */
    private final Map<String, FailureWindow> failures = new ConcurrentHashMap<>();
    private volatile Instant lastPurge = Instant.EPOCH;

    private record FailureWindow(Instant windowStart, int count) {
    }

    public MfaPreAuthServiceImpl(UserService userService,
                                 TotpService totpService,
                                 Clock clock,
                                 @Value("${radius.mfa.ttl-seconds:60}") long ttlSeconds) {
        if (ttlSeconds <= 0) {
            throw new IllegalArgumentException("radius.mfa.ttl-seconds must be positive");
        }
        this.userService = userService;
        this.totpService = totpService;
        this.clock = clock;
        this.approvalTtl = Duration.ofSeconds(ttlSeconds);
    }

    public Duration getApprovalTtl() {
        return approvalTtl;
    }

    @Override
    public boolean preAuthenticate(String username, Integer otp) {
        String key = UsernameNormalizer.normalize(username);
        if (key == null || otp == null || otp < 0) {
            return false;
        }
        Instant now = clock.instant();
        purgeIfDue(now);

        if (isLockedOut(key, now)) {
            log.warn("MFA pre-authentication rejected for locked-out user '{}'", key);
            return false;
        }

        User user = resolveUser(username, key);
        if (user == null || user.getSecret() == null || user.getId() == null) {
            recordFailure(key, now);
            return false;
        }

        OptionalLong step = totpService.findMatchingTimeStep(user.getSecret(), otp);
        if (step.isEmpty() || !markTimeStepUsed(user.getId(), step.getAsLong())) {
            recordFailure(key, now);
            return false;
        }

        failures.remove(key);
        String approvalKey = UsernameNormalizer.normalize(user.getUsername());
        approvals.put(approvalKey, now.plus(approvalTtl));
        log.info("MFA pre-authentication approved for user '{}' (valid {}s)", approvalKey, approvalTtl.getSeconds());
        return true;
    }

    @Override
    public boolean consumeApproval(String username) {
        String key = UsernameNormalizer.normalize(username);
        if (key == null) {
            return false;
        }
        Instant expiry = approvals.remove(key);
        return expiry != null && clock.instant().isBefore(expiry);
    }

    @Override
    public boolean hasActiveApproval(String username) {
        String key = UsernameNormalizer.normalize(username);
        if (key == null) {
            return false;
        }
        Instant expiry = approvals.get(key);
        return expiry != null && clock.instant().isBefore(expiry);
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

    private boolean isLockedOut(String key, Instant now) {
        FailureWindow w = failures.get(key);
        return w != null && w.count() >= MAX_FAILED_ATTEMPTS && now.isBefore(w.windowStart().plus(LOCKOUT_WINDOW));
    }

    private void recordFailure(String key, Instant now) {
        failures.compute(key, (k, w) -> {
            if (w == null || !now.isBefore(w.windowStart().plus(LOCKOUT_WINDOW))) {
                return new FailureWindow(now, 1);
            }
            return new FailureWindow(w.windowStart(), w.count() + 1);
        });
    }

    private void purgeIfDue(Instant now) {
        if (now.isBefore(lastPurge.plus(PURGE_INTERVAL))) {
            return;
        }
        lastPurge = now;
        approvals.entrySet().removeIf(e -> !now.isBefore(e.getValue()));
        failures.entrySet().removeIf(e -> !now.isBefore(e.getValue().windowStart().plus(LOCKOUT_WINDOW)));
    }
}
