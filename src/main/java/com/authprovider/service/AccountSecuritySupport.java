package com.authprovider.service;

/**
 * Exposes the cluster-wide account security state (shared lockout, OTP usage and pending-session
 * invalidation). Implemented by the application's {@link UserService} so that components created without
 * dependency injection from a real user service still join the same security boundary instead of
 * silently falling back to node-local state.
 */
public interface AccountSecuritySupport {

    AccountLockoutService accountLockoutService();

    OtpUsageStore otpUsageStore();

    default PendingAuthSessionInvalidator sessionInvalidator() {
        AccountLockoutService lockout = accountLockoutService();
        return lockout == null ? null : lockout.sessionInvalidator();
    }

    static AccountSecuritySupport of(Object candidate) {
        return candidate instanceof AccountSecuritySupport support ? support : null;
    }
}
