package com.authprovider.service;

import com.authprovider.dto.OtpValidationResponse;

import java.util.Optional;

public interface UserOtpService {
    Optional<String> generateSecretForUser(Long userId);
    Optional<Boolean> validateUserOtp(Long userId, Integer otp);
    Optional<Boolean> validateUserOcra(Long userId, String challenge, String otp);

    String generateSecretForUsername(String username);
    OtpValidationResponse validateOtpByUsername(String username, String otp);
    OtpValidationResponse validateOcraByUsername(String username, String challenge, String otp);

    /**
     * Validates a TOTP on behalf of the OAuth 2.0 client {@code oauthClientId} (database id): the user must hold
     * an enabled assignment to that client. {@code null} validates without a client context.
     */
    default OtpValidationResponse validateOtpByUsername(String username, String otp, Long oauthClientId) {
        return validateOtpByUsername(username, otp);
    }

    /** OCRA counterpart of {@link #validateOtpByUsername(String, String, Long)}. */
    default OtpValidationResponse validateOcraByUsername(String username, String challenge, String otp,
                                                        Long oauthClientId) {
        return validateOcraByUsername(username, challenge, otp);
    }

    /**
     * Validates an OTP after the caller has already verified the user's primary password, enabling
     * second-factor token brute-force lockout protection across linked accounts.
     */
    default Optional<Boolean> validatePrimaryVerifiedOtp(Long userId, Integer otp) {
        return validateUserOtp(userId, otp);
    }
}
