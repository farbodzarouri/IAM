package com.authprovider.service;

import java.util.Optional;

public interface UserOtpService {
    Optional<String> generateSecretForUser(Long userId);
    Optional<Boolean> validateUserOtp(Long userId, Integer otp);
    Optional<Boolean> validateUserOcra(Long userId, String challenge, String otp);

    /**
     * Whether {@link #validateUserOtp} / {@link #validateUserOcra} themselves enforce the shared account
     * protections (lockout check, failure accounting, clearing on success and single-use codes). Callers
     * must not record the outcome a second time when this returns {@code true}.
     */
    default boolean enforcesAccountProtection() {
        return false;
    }
}
