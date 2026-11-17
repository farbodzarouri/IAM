package com.authprovider.service;

import com.authprovider.repository.MfaApprovalRepository;
import com.authprovider.repository.RadiusChallengeSessionRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.LongConsumer;

/**
 * Destroys every pending (not yet completed) authentication session of an account: in-band RADIUS
 * challenges and out-of-band MFA pre-authentication approvals. Invoked whenever the account is locked
 * out, deleted, or has its password / OTP secret modified. Persistent sessions are deleted from the
 * shared database (and therefore on every cluster node); node-local stores (used without a database)
 * can register a listener.
 */
@Slf4j
@Component
public class PendingAuthSessionInvalidator {

    private final RadiusChallengeSessionRepository challengeRepository;
    private final MfaApprovalRepository approvalRepository;
    private final List<LongConsumer> listeners = new CopyOnWriteArrayList<>();

    /** Invalidator without persistent stores; only registered listeners are notified. */
    public PendingAuthSessionInvalidator() {
        this(null, null);
    }

    @Autowired
    public PendingAuthSessionInvalidator(RadiusChallengeSessionRepository challengeRepository,
                                         MfaApprovalRepository approvalRepository) {
        this.challengeRepository = challengeRepository;
        this.approvalRepository = approvalRepository;
    }

    /** Registers a callback receiving the id of every account whose pending sessions are invalidated. */
    public void addListener(LongConsumer listener) {
        if (listener != null) {
            listeners.add(listener);
        }
    }

    public void invalidate(Long userId) {
        if (userId == null) {
            return;
        }
        try {
            if (challengeRepository != null) {
                challengeRepository.deleteByUserId(userId);
            }
            if (approvalRepository != null) {
                approvalRepository.deleteByUserId(userId);
            }
        } catch (RuntimeException e) {
            log.error("Unable to invalidate pending authentication sessions of user id {}", userId, e);
            throw e;
        }
        for (LongConsumer listener : listeners) {
            listener.accept(userId);
        }
        log.debug("Invalidated pending authentication sessions of user id {}", userId);
    }
}
