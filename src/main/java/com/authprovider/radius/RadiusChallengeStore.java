package com.authprovider.radius;

import com.authprovider.entity.RadiusChallengeSession;
import com.authprovider.entity.SecurityPolicy;
import com.authprovider.repository.RadiusChallengeSessionRepository;
import com.authprovider.service.SecurityPolicyService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Component;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Pending in-band RADIUS challenge sessions. Sessions are persisted as {@link RadiusChallengeSession}
 * entities so that a challenge issued by one cluster node can be answered on another and survives
 * restarts. Without a repository (unit tests) sessions are kept in memory.
 */
@Slf4j
@Component
public class RadiusChallengeStore {

    static final int STATE_LENGTH = 32;
    private static final int MAX_STATE_ATTEMPTS = 16;

    private final Map<String, ChallengeSession> sessions = new ConcurrentHashMap<>();
    private final SecurityPolicyService policyService;
    private final RadiusChallengeSessionRepository repository;
    private final Clock clock;
    private final SecureRandom secureRandom;

    public RadiusChallengeStore(RadiusProperties properties, Clock clock, SecureRandom secureRandom) {
        this(SecurityPolicyService.fromProperties(properties), null, clock, secureRandom);
    }

    @Autowired
    public RadiusChallengeStore(SecurityPolicyService policyService, RadiusChallengeSessionRepository repository,
                                Clock clock, SecureRandom secureRandom) {
        this.policyService = policyService;
        this.repository = repository;
        this.clock = clock;
        this.secureRandom = secureRandom;
    }

    public record ChallengeSession(Long userId, String userName, InetAddress clientAddress, Instant expiresAt) {
    }

    /** Whether sessions are kept in the shared database (as opposed to node-local memory). */
    public boolean isPersistent() {
        return repository != null;
    }

    public Optional<byte[]> create(Long userId, String userName, InetAddress clientAddress) {
        SecurityPolicy policy = policyService.current();
        int maxPending = policy.getChallengeMaxPending();
        Instant now = clock.instant();
        if (size() >= maxPending) {
            purgeExpired();
        }
        if (pending(now) >= maxPending) {
            return Optional.empty();
        }
        Instant expiresAt = now.plus(Duration.ofSeconds(policy.getChallengeTtlSeconds()));
        if (repository == null) {
            ChallengeSession session = new ChallengeSession(userId, userName, clientAddress, expiresAt);
            while (true) {
                byte[] state = newState();
                if (sessions.putIfAbsent(key(state), session) == null) {
                    return Optional.of(state);
                }
            }
        }
        for (int attempt = 0; attempt < MAX_STATE_ATTEMPTS; attempt++) {
            byte[] state = newState();
            String key = key(state);
            if (repository.existsByState(key)) {
                continue;
            }
            try {
                repository.saveAndFlush(RadiusChallengeSession.builder()
                        .state(key)
                        .userId(userId)
                        .userName(userName)
                        .clientAddress(clientAddress == null ? null : clientAddress.getHostAddress())
                        .createdAt(now)
                        .expiresAt(expiresAt)
                        .build());
                return Optional.of(state);
            } catch (DataIntegrityViolationException e) {
                log.debug("RADIUS State collision; regenerating");
            }
        }
        return Optional.empty();
    }

    /**
     * Returns the pending, non-expired session for {@code state} without consuming it, so that a request
     * that does not match the session (other user or client) leaves the legitimate challenge intact.
     */
    public Optional<ChallengeSession> peek(byte[] state) {
        if (state == null || state.length != STATE_LENGTH) {
            return Optional.empty();
        }
        Instant now = clock.instant();
        if (repository == null) {
            ChallengeSession session = sessions.get(key(state));
            if (session == null || !now.isBefore(session.expiresAt())) {
                return Optional.empty();
            }
            return Optional.of(session);
        }
        return repository.findByState(key(state))
                .filter(entity -> now.isBefore(entity.getExpiresAt()))
                .map(RadiusChallengeStore::toSession);
    }

    /** Atomically consumes the session (single use across the cluster). */
    public Optional<ChallengeSession> consume(byte[] state) {
        if (state == null || state.length != STATE_LENGTH) {
            return Optional.empty();
        }
        Instant now = clock.instant();
        if (repository == null) {
            ChallengeSession session = sessions.remove(key(state));
            if (session == null || !now.isBefore(session.expiresAt())) {
                return Optional.empty();
            }
            return Optional.of(session);
        }
        Optional<RadiusChallengeSession> stored = repository.findByState(key(state));
        if (stored.isEmpty()) {
            return Optional.empty();
        }
        RadiusChallengeSession entity = stored.get();
        // Single-use across the cluster: only the caller whose delete removed the row may proceed.
        if (repository.deleteByIdReturningCount(entity.getId()) != 1) {
            return Optional.empty();
        }
        if (!now.isBefore(entity.getExpiresAt())) {
            return Optional.empty();
        }
        return Optional.of(toSession(entity));
    }

    /** Invalidates every pending challenge of an account (lockout, deletion, credential change). */
    public void invalidateUser(Long userId) {
        if (userId == null) {
            return;
        }
        if (repository == null) {
            sessions.values().removeIf(session -> userId.equals(session.userId()));
            return;
        }
        repository.deleteByUserId(userId);
    }

    private static ChallengeSession toSession(RadiusChallengeSession entity) {
        return new ChallengeSession(entity.getUserId(), entity.getUserName(),
                parseAddress(entity.getClientAddress()), entity.getExpiresAt());
    }

    public void purgeExpired() {
        Instant now = clock.instant();
        if (repository == null) {
            sessions.values().removeIf(session -> !now.isBefore(session.expiresAt()));
            return;
        }
        repository.deleteExpired(now);
    }

    public int size() {
        if (repository == null) {
            return sessions.size();
        }
        return (int) Math.min(Integer.MAX_VALUE, repository.count());
    }

    private long pending(Instant now) {
        if (repository == null) {
            return sessions.values().stream().filter(session -> now.isBefore(session.expiresAt())).count();
        }
        return repository.countByExpiresAtAfter(now);
    }

    private byte[] newState() {
        byte[] state = new byte[STATE_LENGTH];
        secureRandom.nextBytes(state);
        return state;
    }

    private static InetAddress parseAddress(String address) {
        if (address == null || !CidrBlock.isValid(address)) {
            return null;
        }
        try {
            return InetAddress.getByName(address);
        } catch (UnknownHostException e) {
            return null;
        }
    }

    private static String key(byte[] state) {
        return Base64.getEncoder().encodeToString(state);
    }
}
