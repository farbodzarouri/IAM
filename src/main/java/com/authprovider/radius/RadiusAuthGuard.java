package com.authprovider.radius;

import com.authprovider.service.AccountLockoutService;
import com.authprovider.service.AuthFailureStore;
import com.authprovider.service.InMemoryAuthFailureStore;
import com.authprovider.service.SecurityPolicyService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.time.Clock;

/**
 * Brute-force protection for RADIUS authentication. Lockout state is the account-wide state of the
 * shared {@link AccountLockoutService}: failures recorded here count together with failures of every
 * other channel (web login, MFA pre-authentication, direct OTP / OCRA validation) and a lockout reached on
 * any channel blocks RADIUS as well.
 */
@Slf4j
@Component
public class RadiusAuthGuard {

    private final AccountLockoutService lockoutService;

    public RadiusAuthGuard(SecurityPolicyService policyService, Clock clock) {
        this(policyService, new InMemoryAuthFailureStore(), clock);
    }

    public RadiusAuthGuard(SecurityPolicyService policyService, AuthFailureStore failureStore, Clock clock) {
        this(new AccountLockoutService(policyService, failureStore, clock));
    }

    @Autowired
    public RadiusAuthGuard(AccountLockoutService lockoutService) {
        this.lockoutService = lockoutService;
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

    public void purgeExpired() {
        lockoutService.purgeExpired();
    }
}
