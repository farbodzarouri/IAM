package com.authprovider.service;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * Centralizes password encoding, verification, and timing-equalization checks across all
 * authentication channels and account management services.
 */
public interface PasswordService {

    /**
     * Encodes a raw password using the configured {@code PasswordEncoder}. Already-encoded BCrypt
     * hashes (with or without {@code {bcrypt}} prefix) are returned normalized without double-hashing.
     */
    String encode(String rawPassword);

    /** Returns {@code true} if {@code password} is already in an encoded BCrypt format. */
    boolean isEncoded(String password);

    /** Constant-time/BCrypt comparison of a stored credential against a candidate raw password. */
    boolean matches(String storedPassword, String candidatePassword);

    /** Performs a dummy password verification to equalize response timing for unknown/blocked accounts. */
    void simulateCheck(String candidatePassword);

    /** Standalone instance using BCrypt for unit tests constructed without Spring injection. */
    static PasswordService withDefaults() {
        return new PasswordServiceImpl(new BCryptPasswordEncoder());
    }
}
