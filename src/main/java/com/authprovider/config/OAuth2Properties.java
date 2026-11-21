package com.authprovider.config;

import lombok.Data;
import lombok.ToString;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * OAuth 2.0 authorization server settings for machine-to-machine clients. Registered clients, signing keys
 * and token revocations are stored in the database; these properties must be identical on every node of a
 * cluster.
 */
@Data
@ConfigurationProperties(prefix = "iam.oauth2")
public class OAuth2Properties implements InitializingBean {

    /** {@code iss} claim of issued access tokens (RFC 9068 section 2.2). */
    private String issuer = "urn:authprovider:iam";
    /** {@code aud} claim: resource indicator of the protected IAM API. */
    private String audience = "urn:authprovider:iam:api";
    /** Access token lifetime. */
    private long accessTokenTtlSeconds = 300;
    /** Tolerated clock difference between cluster nodes when validating {@code exp}, {@code iat}, {@code nbf}. */
    private long clockSkewSeconds = 30;
    /** RSA modulus size of generated signing keys. */
    private int signingKeySize = 2048;
    /** Interval after which a new signing key is generated; previous keys stay published until their tokens expire. */
    private long signingKeyRotationSeconds = 30L * 24 * 3600;
    /** How long a node caches signing keys loaded from the database. */
    private long keyCacheSeconds = 30;
    /**
     * Optional secret protecting the private signing keys at rest (AES-256-GCM, PBKDF2-derived key). Supply
     * via environment / secret store, never in source control.
     */
    @ToString.Exclude
    private String keyEncryptionSecret;

    @Override
    public void afterPropertiesSet() {
        validate();
    }

    public void validate() {
        if (issuer == null || issuer.isBlank() || audience == null || audience.isBlank()) {
            throw new IllegalStateException("iam.oauth2.issuer and iam.oauth2.audience must be set");
        }
        if (accessTokenTtlSeconds <= 0 || accessTokenTtlSeconds > 86_400) {
            throw new IllegalStateException("iam.oauth2.access-token-ttl-seconds must be between 1 and 86400");
        }
        if (clockSkewSeconds < 0 || clockSkewSeconds > 300) {
            throw new IllegalStateException("iam.oauth2.clock-skew-seconds must be between 0 and 300");
        }
        if (signingKeySize < 2048 || signingKeySize > 8192) {
            throw new IllegalStateException("iam.oauth2.signing-key-size must be between 2048 and 8192");
        }
        if (signingKeyRotationSeconds < 3600) {
            throw new IllegalStateException("iam.oauth2.signing-key-rotation-seconds must be at least 3600");
        }
        if (keyCacheSeconds <= 0 || keyCacheSeconds > 3600) {
            throw new IllegalStateException("iam.oauth2.key-cache-seconds must be between 1 and 3600");
        }
    }
}
