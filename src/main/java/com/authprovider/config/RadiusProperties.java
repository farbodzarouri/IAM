package com.authprovider.config;

import lombok.Data;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * UDP listener, worker pool, and duplicate-packet cache startup settings for the embedded
 * RADIUS server. Runtime security policies and NAS shared secrets are persisted in the database
 * ({@code security_policies} and {@code radius_clients}).
 */
@Data
@ConfigurationProperties(prefix = "radius")
public class RadiusProperties implements InitializingBean {

    private boolean enabled = true;
    private int port = 1812;
    private String bindAddress;
    private int workerThreads = 8;
    private int workerQueueCapacity = 1_000;
    private long duplicateCacheSeconds = 30;
    private int maxDuplicateCacheEntries = 100_000;

    @Override
    public void afterPropertiesSet() {
        validate();
    }

    public void validate() {
        if (port < 0 || port > 65535) {
            throw new IllegalStateException("radius.port must be between 0 and 65535");
        }
        if (workerThreads <= 0 || workerQueueCapacity <= 0) {
            throw new IllegalStateException("radius.worker-threads and radius.worker-queue-capacity must be positive");
        }
        if (duplicateCacheSeconds <= 0 || maxDuplicateCacheEntries <= 0) {
            throw new IllegalStateException("radius duplicate cache settings must be positive");
        }
    }
}
