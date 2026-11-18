package com.authprovider.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * Persistent operational security parameters (lockout thresholds, failure windows and challenge
 * timeouts). The policy named {@link #DEFAULT_NAME} is the one in effect.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "security_policies", uniqueConstraints = {
        @UniqueConstraint(name = "uk_security_policies_name", columnNames = {"name"})
})
public class SecurityPolicy {

    public static final String DEFAULT_NAME = "default";

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "name", nullable = false, length = 64)
    private String name;

    /** RADIUS: consecutive failures before the account is temporarily locked. */
    @Builder.Default
    @Column(name = "max_failures", nullable = false)
    private int maxFailures = 5;

    /** RADIUS: lockout duration once {@link #maxFailures} is reached. */
    @Builder.Default
    @Column(name = "lockout_seconds", nullable = false)
    private long lockoutSeconds = 300;

    /** RADIUS: failures further apart than this window do not accumulate. */
    @Builder.Default
    @Column(name = "failure_window_seconds", nullable = false)
    private long failureWindowSeconds = 300;

    /** In-band RADIUS Access-Challenge State lifetime. */
    @Builder.Default
    @Column(name = "challenge_ttl_seconds", nullable = false)
    private long challengeTtlSeconds = 60;

    /** Maximum concurrently pending challenge sessions. */
    @Builder.Default
    @Column(name = "challenge_max_pending", nullable = false)
    private int challengeMaxPending = 10_000;

    /** Out-of-band MFA approval lifetime. */
    @Builder.Default
    @Column(name = "mfa_approval_ttl_seconds", nullable = false)
    private long mfaApprovalTtlSeconds = 60;

    /** MFA pre-authentication: failed attempts within the window before lockout. */
    @Builder.Default
    @Column(name = "mfa_max_failed_attempts", nullable = false)
    private int mfaMaxFailedAttempts = 5;

    /** MFA pre-authentication: failure window / lockout duration. */
    @Builder.Default
    @Column(name = "mfa_lockout_window_seconds", nullable = false)
    private long mfaLockoutWindowSeconds = 900;

    /** RADIUS: period during which an accepted OTP value may not be reused. */
    @Builder.Default
    @Column(name = "otp_reuse_window_seconds", nullable = false)
    private long otpReuseWindowSeconds = 120;

    /** RADIUS: require RFC 3579 Message-Authenticator on every Access-Request. */
    @Builder.Default
    @Column(name = "require_message_authenticator", nullable = false)
    private boolean requireMessageAuthenticator = false;

    /** Whether DOMAIN\\user and user@realm forms strip the realm when matching local accounts. */
    @Builder.Default
    @Column(name = "strip_realm", nullable = false)
    private boolean stripRealm = true;

    /** RADIUS Access-Challenge Reply-Message prompt. */
    @Builder.Default
    @Column(name = "challenge_prompt", nullable = false, length = 253)
    private String challengePrompt = "Enter your one-time passcode";

    /** Whether Out-of-Band RADIUS (Access-Request without User-Password via /mfa pre-auth) is enabled. */
    @Builder.Default
    @Column(name = "mfa_out_of_band_enabled", nullable = false)
    private boolean mfaOutOfBandEnabled = true;

    /** Default authentication mode when a RADIUS client or User does not specify an override. */
    @Builder.Default
    @Enumerated(EnumType.STRING)
    @Column(name = "default_auth_mode", nullable = false, length = 32)
    private AuthMode defaultAuthMode = AuthMode.PASSWORD_AND_OTP;

    @Column(name = "updated_at")
    private Instant updatedAt;

    public AuthMode getDefaultAuthMode() {
        return defaultAuthMode == null ? AuthMode.PASSWORD_AND_OTP : defaultAuthMode;
    }

    @PrePersist
    @PreUpdate
    void touch() {
        updatedAt = Instant.now();
    }
}
