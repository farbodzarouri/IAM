package com.authprovider.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * Access token revoked via RFC 7009, identified by its {@code jti}. Rows are kept until the token would
 * have expired anyway and are shared by all cluster nodes.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "oauth_revoked_tokens", uniqueConstraints = {
        @UniqueConstraint(name = "uk_oauth_revoked_tokens_jti", columnNames = {"jti"})
}, indexes = {
        @Index(name = "idx_oauth_revoked_tokens_expires_at", columnList = "expires_at")
})
public class OAuthRevokedToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "jti", nullable = false, length = 64)
    private String jti;

    @Column(name = "client_id", nullable = false, length = 128)
    private String clientId;

    @Column(name = "revoked_at", nullable = false)
    private Instant revokedAt;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;
}
