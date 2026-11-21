package com.authprovider.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.Immutable;

import java.time.Instant;

/**
 * Append-only audit record of an authentication attempt. Rows are never updated or deleted by the
 * application ({@link Immutable}, non-updatable columns and lifecycle guards).
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Immutable
@Table(name = "auth_audit_logs", indexes = {
        @Index(name = "idx_auth_audit_logs_occurred_at", columnList = "occurred_at"),
        @Index(name = "idx_auth_audit_logs_username", columnList = "username")
})
public class AuthAuditLog {

    public enum Channel {
        WEB_LOGIN,
        MFA_PREAUTH,
        RADIUS,
        ADMIN_LOGIN,
        OTP_VALIDATION,
        /** RFC 6749 token endpoint (client authentication and token issuance). */
        OAUTH2_TOKEN,
        /** RFC 7662 token introspection endpoint. */
        OAUTH2_INTROSPECTION,
        /** RFC 7009 token revocation endpoint. */
        OAUTH2_REVOCATION,
        /** RFC 6750 bearer token rejected by a protected endpoint. */
        OAUTH2_BEARER,
        /** Administrative changes to registered OAuth 2.0 clients. */
        OAUTH2_CLIENT_ADMIN
    }

    public enum Outcome {
        SUCCESS,
        CHALLENGE,
        ENROLLMENT_REQUIRED,
        FAILURE,
        LOCKED,
        ERROR
    }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "occurred_at", nullable = false, updatable = false)
    private Instant occurredAt;

    @Enumerated(EnumType.STRING)
    @Column(name = "channel", nullable = false, length = 32, updatable = false)
    private Channel channel;

    @Column(name = "username", length = 256, updatable = false)
    private String username;

    @Column(name = "user_id", updatable = false)
    private Long userId;

    @Column(name = "client_address", length = 64, updatable = false)
    private String clientAddress;

    /** Name of the RADIUS client, OAuth 2.0 client id, or LDAP directory involved, if any. */
    @Column(name = "client_name", length = 128, updatable = false)
    private String clientName;

    @Enumerated(EnumType.STRING)
    @Column(name = "outcome", nullable = false, length = 32, updatable = false)
    private Outcome outcome;

    /** Machine-readable reason (e.g. INVALID_CREDENTIALS, INVALID_OTP, LOCKED_OUT). */
    @Column(name = "reason", length = 128, updatable = false)
    private String reason;

    /** Authentication source: LOCAL or LDAP. */
    @Column(name = "source", length = 32, updatable = false)
    private String source;

    @PreUpdate
    @PreRemove
    void preventModification() {
        throw new UnsupportedOperationException("Audit log entries are append-only");
    }
}
