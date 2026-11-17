package com.authprovider.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/** Node-local {@link OtpUsageStore}, used when no database is available (e.g. unit tests). */
public class InMemoryOtpUsageStore implements OtpUsageStore {

    private final Map<Long, Long> lastTimeSteps = new ConcurrentHashMap<>();
    private final Map<Long, Set<String>> usedChallenges = new ConcurrentHashMap<>();

    @Override
    public boolean consumeTimeStep(Long userId, long timeStep) {
        if (userId == null) {
            return false;
        }
        boolean[] accepted = {false};
        lastTimeSteps.compute(userId, (id, previous) -> {
            if (previous == null || timeStep > previous) {
                accepted[0] = true;
                return timeStep;
            }
            return previous;
        });
        return accepted[0];
    }

    @Override
    public boolean consumeOcraChallenge(Long userId, String challenge) {
        if (userId == null || challenge == null) {
            return false;
        }
        return usedChallenges.computeIfAbsent(userId, id -> ConcurrentHashMap.newKeySet()).add(hash(challenge));
    }

    @Override
    public void resetOcraChallenges(Long userId) {
        if (userId != null) {
            usedChallenges.remove(userId);
        }
    }

    @Override
    public void forgetUser(Long userId) {
        if (userId != null) {
            lastTimeSteps.remove(userId);
            usedChallenges.remove(userId);
        }
    }

    @Override
    public void clear() {
        lastTimeSteps.clear();
        usedChallenges.clear();
    }

    static String hash(String challenge) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(challenge.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
