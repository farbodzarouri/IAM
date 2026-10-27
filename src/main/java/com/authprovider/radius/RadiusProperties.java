package com.authprovider.radius;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

@Data
@Component
@ConfigurationProperties(prefix = "radius")
public class RadiusProperties {

    public static final String DEFAULT_SHARED_SECRET = "secret";

    private boolean enabled = true;
    private int port = 1812;
    private String bindAddress;
    private String sharedSecret = DEFAULT_SHARED_SECRET;
    private boolean requireMessageAuthenticator = false;
    private List<String> allowedClients = new ArrayList<>();
    private boolean stripRealm = true;
    private int maxFailures = 5;
    private long lockoutSeconds = 300;
    private long duplicateCacheSeconds = 30;
    private int maxDuplicateCacheEntries = 100_000;
    private int workerThreads = 8;
    private int workerQueueCapacity = 1_000;
    private Challenge challenge = new Challenge();

    @Data
    public static class Challenge {
        private long ttlSeconds = 60;
        private int maxPending = 10_000;
        private String prompt = "Enter your one-time passcode";
    }

    public byte[] sharedSecretBytes() {
        return sharedSecret == null ? new byte[0] : sharedSecret.getBytes(StandardCharsets.UTF_8);
    }

    public void validate() {
        if (port < 0 || port > 65535) {
            throw new IllegalStateException("radius.port must be between 0 and 65535");
        }
        if (sharedSecret == null || sharedSecret.isEmpty()) {
            throw new IllegalStateException("radius.shared-secret must not be empty");
        }
        if (challenge == null || challenge.getTtlSeconds() <= 0) {
            throw new IllegalStateException("radius.challenge.ttl-seconds must be positive");
        }
        if (challenge.getMaxPending() <= 0) {
            throw new IllegalStateException("radius.challenge.max-pending must be positive");
        }
        if (challenge.getPrompt() == null || challenge.getPrompt().isBlank()
                || challenge.getPrompt().getBytes(StandardCharsets.UTF_8).length > RadiusConstants.MAX_ATTRIBUTE_VALUE_LENGTH) {
            throw new IllegalStateException("radius.challenge.prompt must be 1-253 bytes");
        }
        if (workerThreads <= 0 || workerQueueCapacity <= 0) {
            throw new IllegalStateException("radius.worker-threads and radius.worker-queue-capacity must be positive");
        }
        if (duplicateCacheSeconds <= 0 || maxDuplicateCacheEntries <= 0) {
            throw new IllegalStateException("radius duplicate cache settings must be positive");
        }
        if (maxFailures <= 0 || lockoutSeconds <= 0) {
            throw new IllegalStateException("radius.max-failures and radius.lockout-seconds must be positive");
        }
    }
}
