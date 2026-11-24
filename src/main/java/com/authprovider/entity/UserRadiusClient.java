package com.authprovider.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.ToString;
import org.hibernate.annotations.ColumnDefault;
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;

import java.time.Instant;

/**
 * Assignment of a {@link User} to a RADIUS client. A user can only authenticate (or validate OTP / MFA)
 * through a client it holds an enabled assignment for. The optional {@code authMode} overrides the
 * client's authentication mode for this user ({@code null} inherits the client / policy default).
 * Assignments are removed together with their user or client.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "user_radius_clients", uniqueConstraints = {
        @UniqueConstraint(name = "uk_user_radius_clients_user_client", columnNames = {"user_id", "client_id"})
})
public class UserRadiusClient {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    @ManyToOne(fetch = FetchType.EAGER, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    @OnDelete(action = OnDeleteAction.CASCADE)
    private User user;

    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    @ManyToOne(fetch = FetchType.EAGER, optional = false)
    @JoinColumn(name = "client_id", nullable = false)
    @OnDelete(action = OnDeleteAction.CASCADE)
    private RadiusClient client;

    @Builder.Default
    @ColumnDefault("true")
    @Column(name = "enabled", nullable = false)
    private boolean enabled = true;

    /** Optional per-assignment authentication mode override (null inherits the client / policy default). */
    @Enumerated(EnumType.STRING)
    @Column(name = "auth_mode", length = 32)
    private AuthMode authMode;

    @Column(name = "created_at")
    private Instant createdAt;

    @Column(name = "updated_at")
    private Instant updatedAt;

    @ToString.Include(name = "userId")
    public Long getUserId() {
        return user == null ? null : user.getId();
    }

    @ToString.Include(name = "clientId")
    public Long getClientId() {
        return client == null ? null : client.getId();
    }

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
