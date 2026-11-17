package com.authprovider.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * Brute-force failure tracking and lockout state for one subject within one scope
 * (e.g. RADIUS failures per user id, MFA pre-authentication failures per normalized user name).
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "auth_failure_records", uniqueConstraints = {
        @UniqueConstraint(name = "uk_auth_failure_records_scope_subject", columnNames = {"scope", "subject"})
}, indexes = {
        @Index(name = "idx_auth_failure_records_last_failure", columnList = "last_failure_at")
})
public class AuthFailureRecord {

    public static final String SCOPE_RADIUS = "RADIUS";
    public static final String SCOPE_MFA_PREAUTH = "MFA_PREAUTH";
    /**
     * Account-wide failure tracking (keyed by user id) shared by every authentication channel. It reuses
     * the historical RADIUS scope name so existing records keep their meaning.
     */
    public static final String SCOPE_ACCOUNT = SCOPE_RADIUS;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "scope", nullable = false, length = 32)
    private String scope;

    /** User id or normalized user name, depending on the scope. */
    @Column(name = "subject", nullable = false, length = 256)
    private String subject;

    @Column(name = "failure_count", nullable = false)
    private int failureCount;

    @Column(name = "window_start_at", nullable = false)
    private Instant windowStartAt;

    @Column(name = "last_failure_at", nullable = false)
    private Instant lastFailureAt;

    /** Non-null while (or after) the subject is locked out. */
    @Column(name = "locked_until")
    private Instant lockedUntil;

    @Version
    @Column(name = "version")
    private Long version;
}
