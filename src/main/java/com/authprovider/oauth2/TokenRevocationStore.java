package com.authprovider.oauth2;

import com.authprovider.entity.OAuthRevokedToken;
import com.authprovider.repository.OAuthRevokedTokenRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/**
 * Database-backed denylist of revoked access token identifiers ({@code jti}), consulted on every bearer
 * token use and introspection so that a revocation takes effect immediately on all cluster nodes. Entries
 * are purged once the revoked token has expired.
 */
@Slf4j
@Component
public class TokenRevocationStore {

    private static final Duration PURGE_INTERVAL = Duration.ofMinutes(5);

    private final OAuthRevokedTokenRepository repository;
    private final Clock clock;
    private volatile Instant lastPurge = Instant.EPOCH;

    public TokenRevocationStore(OAuthRevokedTokenRepository repository, Clock clock) {
        this.repository = repository;
        this.clock = clock;
    }

    public boolean isRevoked(String jti) {
        return jti != null && repository.existsByJti(jti);
    }

    /** Idempotently revokes a token; returns {@code true} if this call recorded the revocation. */
    public boolean revoke(String jti, String clientId, Instant expiresAt) {
        Instant now = clock.instant();
        purgeIfDue(now);
        if (repository.existsByJti(jti)) {
            return false;
        }
        try {
            repository.saveAndFlush(OAuthRevokedToken.builder()
                    .jti(jti)
                    .clientId(clientId)
                    .revokedAt(now)
                    .expiresAt(expiresAt)
                    .build());
            return true;
        } catch (DataIntegrityViolationException e) {
            // Revoked concurrently (possibly on another node).
            return false;
        }
    }

    private void purgeIfDue(Instant now) {
        if (now.isBefore(lastPurge.plus(PURGE_INTERVAL))) {
            return;
        }
        lastPurge = now;
        try {
            int removed = repository.deleteExpired(now);
            if (removed > 0) {
                log.debug("Purged {} expired token revocation(s)", removed);
            }
        } catch (RuntimeException e) {
            log.warn("Unable to purge expired token revocations: {}", e.toString());
        }
    }
}
