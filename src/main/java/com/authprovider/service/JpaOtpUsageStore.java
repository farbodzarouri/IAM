package com.authprovider.service;

import com.authprovider.entity.OcraChallengeUse;
import com.authprovider.entity.OtpReplayState;
import com.authprovider.repository.OcraChallengeUseRepository;
import com.authprovider.repository.OtpReplayStateRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Clock;

/**
 * Database-backed {@link OtpUsageStore}. TOTP time steps advance through a single conditional
 * {@code UPDATE ... WHERE last_time_step < :step} (atomic in the database, hence across threads, channels
 * and cluster nodes); the first acceptance for a user inserts the row, with concurrent inserts resolved by
 * the unique constraint. OCRA challenge use is recorded under a unique (user, challenge) constraint.
 */
@Slf4j
@Component
public class JpaOtpUsageStore implements OtpUsageStore {

    private static final int MAX_ATTEMPTS = 5;

    private final OtpReplayStateRepository replayRepository;
    private final OcraChallengeUseRepository ocraRepository;
    private final TransactionTemplate requiresNew;
    private final Clock clock;

    public JpaOtpUsageStore(OtpReplayStateRepository replayRepository, OcraChallengeUseRepository ocraRepository,
                            PlatformTransactionManager transactionManager, Clock clock) {
        this.replayRepository = replayRepository;
        this.ocraRepository = ocraRepository;
        this.requiresNew = new TransactionTemplate(transactionManager);
        this.requiresNew.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        this.clock = clock;
    }

    @Override
    public boolean consumeTimeStep(Long userId, long timeStep) {
        if (userId == null) {
            return false;
        }
        for (int attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
            if (replayRepository.advance(userId, timeStep, clock.instant()) == 1) {
                return true;
            }
            if (replayRepository.existsByUserId(userId)) {
                return false;
            }
            try {
                requiresNew.executeWithoutResult(status -> replayRepository.saveAndFlush(OtpReplayState.builder()
                        .userId(userId)
                        .lastTimeStep(timeStep)
                        .updatedAt(clock.instant())
                        .build()));
                return true;
            } catch (DataIntegrityViolationException e) {
                // Another request created the row concurrently; retry the conditional update.
                log.debug("Concurrent first OTP use for user id {} (attempt {})", userId, attempt + 1);
            }
        }
        return false;
    }

    @Override
    public boolean consumeOcraChallenge(Long userId, String challenge) {
        if (userId == null || challenge == null) {
            return false;
        }
        String hash = InMemoryOtpUsageStore.hash(challenge);
        if (ocraRepository.existsByUserIdAndChallengeHash(userId, hash)) {
            return false;
        }
        try {
            requiresNew.executeWithoutResult(status -> ocraRepository.saveAndFlush(OcraChallengeUse.builder()
                    .userId(userId)
                    .challengeHash(hash)
                    .usedAt(clock.instant())
                    .build()));
            return true;
        } catch (DataIntegrityViolationException e) {
            return false;
        }
    }

    @Override
    public void resetOcraChallenges(Long userId) {
        if (userId != null) {
            ocraRepository.deleteByUserId(userId);
        }
    }

    @Override
    public void forgetUser(Long userId) {
        if (userId != null) {
            replayRepository.deleteByUserId(userId);
            ocraRepository.deleteByUserId(userId);
        }
    }

    @Override
    public void clear() {
        replayRepository.deleteAllInBatch();
        ocraRepository.deleteAllInBatch();
    }
}
