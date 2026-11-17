package com.authprovider.radius;

import com.authprovider.entity.AuthFailureRecord;
import com.authprovider.service.AccountLockoutService;
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
 * Brute-force protection for RADIUS authentication. Lockout state is the account-wide state of the
 * shared {@link AccountLockoutService}: failures recorded here count together with failures of every
 * other channel (web login, MFA pre-authentication, direct OTP / OCRA validation) and a lockout reached on
 * any channel blocks RADIUS as well.
 */
@Slf4j
@Component
public class RadiusAuthGuard {

    static final Duration OTP_REUSE_WINDOW = Duration.ofSeconds(120);
    static final String SCOPE = AuthFailureRecord.SCOPE_RADIUS;

    private final Map<String, Instant> usedOtps = new ConcurrentHashMap<>();
    private final AccountLockoutService lockoutService;
    private final SecurityPolicyService policyService;
    private final Clock clock;

    public RadiusAuthGuard(RadiusProperties properties, Clock clock) {
        this(SecurityPolicyService.fromProperties(properties), new InMemoryAuthFailureStore(), clock);
    }

    public RadiusAuthGuard(SecurityPolicyService policyService, AuthFailureStore failureStore, Clock clock) {
        this(new AccountLockoutService(policyService, failureStore, clock), policyService, clock);
    }

    @Autowired
    public RadiusAuthGuard(AccountLockoutService lockoutService, SecurityPolicyService policyService, Clock clock) {
        this.lockoutService = lockoutService;
        this.policyService = policyService;
        this.clock = clock;
    }

    public AccountLockoutService getLockoutService() {
        return lockoutService;
    }

    public boolean isLocked(Long userId) {
        return lockoutService.isLocked(userId);
    }

    public void recordFailure(Long userId) {
        lockoutService.recordFailure(userId);
    }

    public void recordSuccess(Long userId) {
        lockoutService.recordSuccess(userId);
    }

    /**
     * Node-local, best-effort OTP reuse cache. Authoritative single-use enforcement is performed by the
     * shared OTP verification (see {@code OtpVerificationService}); this only protects deployments whose
     * {@code UserOtpService} does not enforce it itself.
     */
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
        usedOtps.values().removeIf(expiry -> !now.isBefore(expiry));
        lockoutService.purgeExpired();
    }

    private Duration otpReuseWindow() {
        long seconds = policyService.current().getOtpReuseWindowSeconds();
        return seconds > 0 ? Duration.ofSeconds(seconds) : OTP_REUSE_WINDOW;
    }
}
