package com.authprovider.service;

/**
 * Single-use bookkeeping for second-factor codes, shared by every authentication channel. Implementations
 * must make each operation atomic with respect to concurrent callers (including other cluster nodes when
 * the store is persistent).
 */
public interface OtpUsageStore {

    /**
     * Accepts the TOTP time step only if it is strictly greater than every time step previously accepted
     * for the user (on any channel). Returns {@code false} for a replayed or older time step.
     */
    boolean consumeTimeStep(Long userId, long timeStep);

    /** Marks the OCRA challenge as answered for the user; returns {@code false} if it was already used. */
    boolean consumeOcraChallenge(Long userId, String challenge);

    /** Forgets OCRA challenge usage of a user (after its OTP secret changed). */
    void resetOcraChallenges(Long userId);

    /** Removes all state of a deleted user. */
    void forgetUser(Long userId);

    /** Removes all replay state (maintenance / test hook). */
    void clear();
}
