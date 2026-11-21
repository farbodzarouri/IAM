package com.authprovider.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

import java.time.Instant;

/**
 * RSA key pair used to sign (RS256) and verify JWT access tokens. Keys live in the shared database so that
 * every cluster node signs with the same key and publishes the same JWK Set. The private key is stored as
 * PKCS#8, AES-GCM encrypted when {@code iam.oauth2.key-encryption-secret} is configured.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "oauth_signing_keys", uniqueConstraints = {
        @UniqueConstraint(name = "uk_oauth_signing_keys_kid", columnNames = {"kid"})
}, indexes = {
        @Index(name = "idx_oauth_signing_keys_verify_until", columnList = "verify_until")
})
public class OAuthSigningKey {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** RFC 7638 JWK thumbprint. */
    @Column(name = "kid", nullable = false, length = 64)
    private String kid;

    /** Base64 X.509 SubjectPublicKeyInfo. */
    @Column(name = "public_key", nullable = false, length = 2048)
    private String publicKey;

    @ToString.Exclude
    @Column(name = "private_key", nullable = false, length = 8192)
    private String privateKey;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    /** Used for signing from this instant (successor keys are published ahead of activation). */
    @Column(name = "sign_from", nullable = false)
    private Instant signFrom;

    /** No longer used for signing after this instant. */
    @Column(name = "sign_until", nullable = false)
    private Instant signUntil;

    /** Published and accepted for verification until this instant. */
    @Column(name = "verify_until", nullable = false)
    private Instant verifyUntil;
}
