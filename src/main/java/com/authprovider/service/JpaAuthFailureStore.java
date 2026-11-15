package com.authprovider.service;

import com.authprovider.entity.AuthFailureRecord;
import com.authprovider.repository.AuthFailureRecordRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.ConcurrencyFailureException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Instant;
import java.util.Optional;
import java.util.function.UnaryOperator;

/**
 * Database-backed {@link AuthFailureStore}: failure counters and lockouts survive restarts and are
 * shared by all cluster nodes. Updates run in their own transaction under a row lock and are retried
 * on concurrent insert / optimistic-lock conflicts.
 */
@Slf4j
@Component
public class JpaAuthFailureStore implements AuthFailureStore {

    private static final int MAX_ATTEMPTS = 5;

    private final AuthFailureRecordRepository repository;
    private final TransactionTemplate transactionTemplate;

    public JpaAuthFailureStore(AuthFailureRecordRepository repository, PlatformTransactionManager transactionManager) {
        this.repository = repository;
        this.transactionTemplate = new TransactionTemplate(transactionManager);
    }

    @Override
    public Optional<FailureState> get(String scope, String subject) {
        return repository.findByScopeAndSubject(scope, subject).map(JpaAuthFailureStore::toState);
    }

    @Override
    public void update(String scope, String subject, UnaryOperator<FailureState> update, boolean createIfAbsentAllowed) {
        RuntimeException last = null;
        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            try {
                transactionTemplate.executeWithoutResult(status -> applyUpdate(scope, subject, update, createIfAbsentAllowed));
                return;
            } catch (DataIntegrityViolationException | ConcurrencyFailureException e) {
                last = e;
                log.debug("Concurrent update of failure record {}/{} (attempt {}): {}", scope, subject, attempt, e.toString());
            }
        }
        throw last;
    }

    private void applyUpdate(String scope, String subject, UnaryOperator<FailureState> update, boolean createIfAbsentAllowed) {
        Optional<AuthFailureRecord> existing = repository.findWithLockByScopeAndSubject(scope, subject);
        if (existing.isEmpty() && !createIfAbsentAllowed) {
            return;
        }
        FailureState next = update.apply(existing.map(JpaAuthFailureStore::toState).orElse(null));
        if (next == null) {
            existing.ifPresent(repository::delete);
            return;
        }
        AuthFailureRecord record = existing.orElseGet(() -> AuthFailureRecord.builder()
                .scope(scope)
                .subject(subject)
                .build());
        record.setFailureCount(next.count());
        record.setWindowStartAt(next.windowStart());
        record.setLastFailureAt(next.lastFailure());
        record.setLockedUntil(next.lockedUntil());
        repository.saveAndFlush(record);
    }

    @Override
    public void delete(String scope, String subject) {
        repository.deleteByScopeAndSubject(scope, subject);
    }

    @Override
    public void purgeExpired(String scope, Instant windowCutoff, Instant now) {
        repository.deleteExpired(scope, windowCutoff, now);
    }

    @Override
    public long count(String scope) {
        return repository.countByScope(scope);
    }

    private static FailureState toState(AuthFailureRecord record) {
        return new FailureState(record.getFailureCount(), record.getWindowStartAt(), record.getLastFailureAt(),
                record.getLockedUntil());
    }
}
