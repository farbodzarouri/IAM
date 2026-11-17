package com.authprovider.service;

/**
 * Pre-authentication of a second factor for Remote Desktop Gateway logins.
 * A successful {@link #preAuthenticate} records a single-use, time-limited approval
 * which is later consumed by the RADIUS server when NPS forwards the Access-Request.
 */
public interface MfaPreAuthService {

    /**
     * Validates the user's OTP and, if valid, records an MFA approval.
     *
     * @return true if the OTP was accepted and an approval is now pending
     */
    boolean preAuthenticate(String username, Integer otp);

    /**
     * Atomically consumes a pending, non-expired approval for the given (RADIUS) user name.
     *
     * @return true if an approval existed and has now been consumed
     */
    boolean consumeApproval(String username);

    /**
     * Atomically consumes a pending, non-expired approval for the given user name, but only if it was
     * issued for the local account {@code userId}. An approval belonging to another account is left
     * untouched.
     */
    default boolean consumeApproval(String username, Long userId) {
        return consumeApproval(username);
    }

    /** @return true if a non-expired, unconsumed approval exists (does not consume it). */
    boolean hasActiveApproval(String username);

    /** Discards all pending approvals of an account (lockout, deletion, credential change). */
    default void invalidateApprovals(Long userId) {
    }
}
