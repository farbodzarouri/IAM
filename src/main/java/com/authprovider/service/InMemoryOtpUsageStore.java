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

    private final Map<String, Long> lastTimeSteps = new ConcurrentHashMap<>();
    private final Map<String, Set<String>> usedChallenges = new ConcurrentHashMap<>();

    @Override
    public boolean consumeTimeStep(Long userId, long timeStep) {
        return userId != null && consumeTimeStepKey(userKey(userId), timeStep);
    }

    @Override
    public boolean consumeTokenTimeStep(Long tokenId, long timeStep) {
        return tokenId != null && consumeTimeStepKey(tokenKey(tokenId), timeStep);
    }

    @Override
    public boolean consumeOcraChallenge(Long userId, String challenge) {
        return userId != null && consumeOcraChallengeKey(userKey(userId), challenge);
    }

    @Override
    public boolean consumeTokenOcraChallenge(Long tokenId, String challenge) {
        return tokenId != null && consumeOcraChallengeKey(tokenKey(tokenId), challenge);
    }

    @Override
    public void resetOcraChallenges(Long userId) {
        if (userId != null) {
            usedChallenges.remove(userKey(userId));
        }
    }

    @Override
    public void resetTokenOcraChallenges(Long tokenId) {
        if (tokenId != null) {
            usedChallenges.remove(tokenKey(tokenId));
        }
    }

    @Override
    public void forgetUser(Long userId) {
        if (userId != null) {
            String key = userKey(userId);
            lastTimeSteps.remove(key);
            usedChallenges.remove(key);
        }
    }

    @Override
    public void forgetToken(Long tokenId) {
        if (tokenId != null) {
            String key = tokenKey(tokenId);
            lastTimeSteps.remove(key);
            usedChallenges.remove(key);
        }
    }

    private boolean consumeTimeStepKey(String subjectKey, long timeStep) {
        boolean[] accepted = {false};
        lastTimeSteps.compute(subjectKey, (id, previous) -> {
            if (previous == null || timeStep > previous) {
                accepted[0] = true;
                return timeStep;
            }
            return previous;
        });
        return accepted[0];
    }

    private boolean consumeOcraChallengeKey(String subjectKey, String challenge) {
        if (challenge == null) {
            return false;
        }
        return usedChallenges.computeIfAbsent(subjectKey, id -> ConcurrentHashMap.newKeySet()).add(hash(challenge));
    }

    private static String userKey(Long userId) {
        return "USER:" + userId;
    }

    private static String tokenKey(Long tokenId) {
        return "TOKEN:" + tokenId;
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
