package com.authprovider.service;

import java.time.Instant;
import java.util.Optional;
import java.util.function.UnaryOperator;

/**
 * Storage of brute-force failure tracking / lockout state, keyed by scope and subject.
 */
public interface AuthFailureStore {

    /** Immutable failure state snapshot. {@code lockedUntil} is {@code null} when not locked. */
    record FailureState(int count, Instant windowStart, Instant lastFailure, Instant lockedUntil) {
    }

    Optional<FailureState> get(String scope, String subject);

    /**
     * Atomically replaces the state of a subject. The function receives the current state (or
     * {@code null}) and returns the new state, or {@code null} to remove the record.
     *
     * @param createIfAbsentAllowed when {@code false} and no record exists, nothing is created
     */
    void update(String scope, String subject, UnaryOperator<FailureState> update, boolean createIfAbsentAllowed);

    void delete(String scope, String subject);

    /** Removes records whose last failure is at or before {@code windowCutoff} and that are not locked at {@code now}. */
    void purgeExpired(String scope, Instant windowCutoff, Instant now);

    long count(String scope);
}
