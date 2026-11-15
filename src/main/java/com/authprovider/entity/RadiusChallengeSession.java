package com.authprovider.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * A pending in-band RADIUS Access-Challenge session (RFC 2865). The opaque {@code State} attribute
 * value is stored Base64 encoded; each session is single-use.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "radius_challenge_sessions", uniqueConstraints = {
        @UniqueConstraint(name = "uk_radius_challenge_sessions_state", columnNames = {"state"})
}, indexes = {
        @Index(name = "idx_radius_challenge_sessions_expires_at", columnList = "expires_at")
})
public class RadiusChallengeSession {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "state", nullable = false, length = 64)
    private String state;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(name = "username", nullable = false, length = 256)
    private String userName;

    @Column(name = "client_address", length = 64)
    private String clientAddress;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;
}
