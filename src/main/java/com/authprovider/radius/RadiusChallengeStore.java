package com.authprovider.radius;

import org.springframework.stereotype.Component;

import java.net.InetAddress;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class RadiusChallengeStore {

    static final int STATE_LENGTH = 32;

    private final Map<String, ChallengeSession> sessions = new ConcurrentHashMap<>();
    private final RadiusProperties properties;
    private final Clock clock;
    private final SecureRandom secureRandom;

    public RadiusChallengeStore(RadiusProperties properties, Clock clock, SecureRandom secureRandom) {
        this.properties = properties;
        this.clock = clock;
        this.secureRandom = secureRandom;
    }

    public record ChallengeSession(Long userId, String userName, InetAddress clientAddress, Instant expiresAt) {
    }

    public Optional<byte[]> create(Long userId, String userName, InetAddress clientAddress) {
        if (sessions.size() >= properties.getChallenge().getMaxPending()) {
            purgeExpired();
            if (sessions.size() >= properties.getChallenge().getMaxPending()) {
                return Optional.empty();
            }
        }
        Instant expiresAt = clock.instant().plus(Duration.ofSeconds(properties.getChallenge().getTtlSeconds()));
        ChallengeSession session = new ChallengeSession(userId, userName, clientAddress, expiresAt);
        while (true) {
            byte[] state = new byte[STATE_LENGTH];
            secureRandom.nextBytes(state);
            if (sessions.putIfAbsent(key(state), session) == null) {
                return Optional.of(state);
            }
        }
    }

    public Optional<ChallengeSession> consume(byte[] state) {
        if (state == null || state.length != STATE_LENGTH) {
            return Optional.empty();
        }
        ChallengeSession session = sessions.remove(key(state));
        if (session == null || !clock.instant().isBefore(session.expiresAt())) {
            return Optional.empty();
        }
        return Optional.of(session);
    }

    public void purgeExpired() {
        Instant now = clock.instant();
        sessions.values().removeIf(session -> !now.isBefore(session.expiresAt()));
    }

    public int size() {
        return sessions.size();
    }

    private static String key(byte[] state) {
        return Base64.getEncoder().encodeToString(state);
    }
}
