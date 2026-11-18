package com.authprovider.service;

import com.authprovider.dto.LoginRequest;
import com.authprovider.dto.LoginResponse;

/**
 * Authenticates {@link com.authprovider.entity.Admin} accounts via local credentials or admin-enabled
 * LDAP directories plus second-factor verification against their {@link com.authprovider.entity.OtpToken}.
 */
public interface AdminLoginService {

    enum PrimaryStatus {
        AUTHENTICATED_NEEDS_OTP,
        AUTHENTICATED_NEEDS_ENROLLMENT,
        INVALID_CREDENTIALS,
        NOT_PROVISIONED,
        DIRECTORY_UNAVAILABLE
    }

    record PrimaryAuthResult(PrimaryStatus status, Long adminId, String username, String source) {
    }

    LoginResponse login(LoginRequest request);

    PrimaryAuthResult verifyPrimary(String username, String password);

    LoginResponse completeOtp(Long adminId, String source, String otp);

    LoginResponse completeEnrollment(Long adminId, String source, String pendingSecret, String otp);
}
