package com.authprovider.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

import java.time.Instant;
import java.util.EnumSet;
import java.util.Set;

/**
 * A registered OAuth 2.0 confidential client (RFC 6749 section 2) of a connected system authenticating
 * machine-to-machine with the {@code client_credentials} grant. The client secret is stored only as a
 * BCrypt hash. {@code tokenVersion} is regenerated whenever security-relevant attributes change (secret,
 * client id, scopes, disabling or blocking), which immediately invalidates every access token issued
 * before the change on all cluster nodes.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "clients", uniqueConstraints = {
        @UniqueConstraint(name = "uk_clients_client_id", columnNames = {"client_id"})
})
public class OAuthClient {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "client_id", nullable = false, length = 128)
    private String clientId;

    @ToString.Exclude
    @Column(name = "client_secret_hash", nullable = false, length = 100)
    private String clientSecretHash;

    @Column(name = "name", nullable = false, length = 128)
    private String name;

    @Builder.Default
    @Column(name = "enabled", nullable = false)
    private boolean enabled = true;

    /** Administrative block; while set the client can neither obtain nor use access tokens. */
    @Builder.Default
    @Column(name = "blocked", nullable = false)
    private boolean blocked = false;

    /** Optional per-client authentication mode override for {@code /v1/api/auth/login} (null inherits policy). */
    @Enumerated(EnumType.STRING)
    @Column(name = "auth_mode", length = 32)
    private AuthMode authMode;

    @Builder.Default
    @Convert(converter = ClientScopeSetConverter.class)
    @Column(name = "scopes", nullable = false, length = 256)
    private Set<ClientScope> scopes = EnumSet.noneOf(ClientScope.class);

    @ToString.Exclude
    @Column(name = "token_version", nullable = false, length = 64)
    private String tokenVersion;

    @Column(name = "secret_rotated_at")
    private Instant secretRotatedAt;

    @Column(name = "created_at")
    private Instant createdAt;

    @Column(name = "updated_at")
    private Instant updatedAt;

    @Version
    @Column(name = "version")
    private Long version;

    @PrePersist
    void onCreate() {
        Instant now = Instant.now();
        if (createdAt == null) {
            createdAt = now;
        }
        updatedAt = now;
    }

    @PreUpdate
    void onUpdate() {
        updatedAt = Instant.now();
    }
}
