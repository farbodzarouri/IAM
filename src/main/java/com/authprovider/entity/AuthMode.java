package com.authprovider.entity;

/**
 * Supported authentication modes for user accounts and RADIUS clients.
 */
public enum AuthMode {
    /** Password followed by TOTP challenge (RADIUS Access-Challenge or REST/form OTP). */
    PASSWORD_AND_OTP,
    /** Single-step password with trailing 6-digit TOTP appended (no challenge round-trip). */
    PASSWORD_AND_OTP_INLINE,
    /** Primary password only (no second factor required). */
    PASSWORD_ONLY,
    /** Second-factor TOTP only (delegated/token-only authentication). */
    OTP_ONLY
}
