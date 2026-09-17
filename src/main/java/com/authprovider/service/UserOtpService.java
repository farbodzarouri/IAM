package com.authprovider.service;

import java.util.Optional;

public interface UserOtpService {
    Optional<String> generateSecretForUser(Long userId);
    Optional<Boolean> validateUserOtp(Long userId, Integer otp);
    Optional<Boolean> validateUserOcra(Long userId, String challenge, String otp);
}
