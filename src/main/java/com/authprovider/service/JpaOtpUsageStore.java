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
        return userId != null && consumeTimeStepBySubject(userKey(userId), userId, timeStep);
    }

    @Override
    public boolean consumeTokenTimeStep(Long tokenId, long timeStep) {
        return tokenId != null && consumeTimeStepBySubject(tokenKey(tokenId), null, timeStep);
    }

    @Override
    public boolean consumeOcraChallenge(Long userId, String challenge) {
        return userId != null && consumeOcraChallengeBySubject(userKey(userId), userId, challenge);
    }

    @Override
    public boolean consumeTokenOcraChallenge(Long tokenId, String challenge) {
        return tokenId != null && consumeOcraChallengeBySubject(tokenKey(tokenId), null, challenge);
    }

    @Override
    public void resetOcraChallenges(Long userId) {
        if (userId != null) {
            ocraRepository.deleteBySubjectKey(userKey(userId));
        }
    }

    @Override
    public void resetTokenOcraChallenges(Long tokenId) {
        if (tokenId != null) {
            ocraRepository.deleteBySubjectKey(tokenKey(tokenId));
        }
    }

    @Override
    public void forgetUser(Long userId) {
        if (userId != null) {
            String key = userKey(userId);
            replayRepository.deleteBySubjectKey(key);
            ocraRepository.deleteBySubjectKey(key);
        }
    }

    @Override
    public void forgetToken(Long tokenId) {
        if (tokenId != null) {
            String key = tokenKey(tokenId);
            replayRepository.deleteBySubjectKey(key);
            ocraRepository.deleteBySubjectKey(key);
        }
    }

    private boolean consumeTimeStepBySubject(String subjectKey, Long userId, long timeStep) {
        for (int attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
            if (replayRepository.advance(subjectKey, timeStep, clock.instant()) == 1) {
                return true;
            }
            if (replayRepository.existsBySubjectKey(subjectKey)) {
                return false;
            }
            try {
                requiresNew.executeWithoutResult(status -> replayRepository.saveAndFlush(OtpReplayState.builder()
                        .subjectKey(subjectKey)
                        .userId(userId)
                        .lastTimeStep(timeStep)
                        .updatedAt(clock.instant())
                        .build()));
                return true;
            } catch (DataIntegrityViolationException e) {
                // Another request created the row concurrently; retry the conditional update.
                log.debug("Concurrent first OTP use for subject {} (attempt {})", subjectKey, attempt + 1);
            }
        }
        return false;
    }

    private boolean consumeOcraChallengeBySubject(String subjectKey, Long userId, String challenge) {
        if (challenge == null) {
            return false;
        }
        String hash = InMemoryOtpUsageStore.hash(challenge);
        if (ocraRepository.existsBySubjectKeyAndChallengeHash(subjectKey, hash)) {
            return false;
        }
        try {
            requiresNew.executeWithoutResult(status -> ocraRepository.saveAndFlush(OcraChallengeUse.builder()
                    .subjectKey(subjectKey)
                    .userId(userId)
                    .challengeHash(hash)
                    .usedAt(clock.instant())
                    .build()));
            return true;
        } catch (DataIntegrityViolationException e) {
            return false;
        }
    }

    private static String userKey(Long userId) {
        return "USER:" + userId;
    }

    private static String tokenKey(Long tokenId) {
        return "TOKEN:" + tokenId;
    }

    @Override
    public void clear() {
        replayRepository.deleteAllInBatch();
        ocraRepository.deleteAllInBatch();
    }
}
