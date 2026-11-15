package com.authprovider.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * A single-use, time-limited out-of-band MFA pre-authentication approval, consumed by the RADIUS
 * server when the gateway forwards an Access-Request without User-Password.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "mfa_approvals", uniqueConstraints = {
        @UniqueConstraint(name = "uk_mfa_approvals_username", columnNames = {"username"})
}, indexes = {
        @Index(name = "idx_mfa_approvals_expires_at", columnList = "expires_at")
})
public class MfaApproval {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** Normalized user name (see {@code UsernameNormalizer}). */
    @Column(name = "username", nullable = false, length = 256)
    private String username;

    @Column(name = "user_id")
    private Long userId;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;
}
