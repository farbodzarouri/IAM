package com.authprovider.service;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.UnaryOperator;

/** Node-local {@link AuthFailureStore}, used when no database is available (e.g. unit tests). */
public class InMemoryAuthFailureStore implements AuthFailureStore {

    private final Map<String, Map<String, FailureState>> states = new ConcurrentHashMap<>();

    private Map<String, FailureState> scope(String scope) {
        return states.computeIfAbsent(scope, s -> new ConcurrentHashMap<>());
    }

    @Override
    public Optional<FailureState> get(String scope, String subject) {
        return Optional.ofNullable(scope(scope).get(subject));
    }

    @Override
    public void update(String scope, String subject, UnaryOperator<FailureState> update, boolean createIfAbsentAllowed) {
        scope(scope).compute(subject, (key, current) -> {
            if (current == null && !createIfAbsentAllowed) {
                return null;
            }
            return update.apply(current);
        });
    }

    @Override
    public void delete(String scope, String subject) {
        scope(scope).remove(subject);
    }

    @Override
    public void purgeExpired(String scope, Instant windowCutoff, Instant now) {
        scope(scope).values().removeIf(state -> !state.lastFailure().isAfter(windowCutoff)
                && (state.lockedUntil() == null || !now.isBefore(state.lockedUntil())));
    }

    @Override
    public long count(String scope) {
        return scope(scope).size();
    }
}
