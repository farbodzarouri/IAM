package com.authprovider.service;

import com.authprovider.entity.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.util.Optional;

/**
 * Direct OTP / OCRA validation and secret management. Validation uses the shared
 * {@link OtpVerificationService}: locked accounts are refused, failures count towards the account-wide
 * lockout, successes clear it, and every accepted code is single-use across all channels.
 */
@Service
public class UserOtpServiceImpl implements UserOtpService {

    private final UserService userService;
    private final SecretGenerator secretGenerator;
    private final OtpVerificationService otpVerifier;

    public UserOtpServiceImpl(UserService userService,
                              SecretGenerator secretGenerator,
                              TotpService totpService,
                              OcraService ocraService) {
        this(userService, secretGenerator, totpService, ocraService, null);
    }

    @Autowired
    public UserOtpServiceImpl(UserService userService,
                              SecretGenerator secretGenerator,
                              TotpService totpService,
                              OcraService ocraService,
                              OtpVerificationService otpVerifier) {
        this.userService = userService;
        this.secretGenerator = secretGenerator;
        this.otpVerifier = otpVerifier != null ? otpVerifier : sharedVerifier(userService, totpService, ocraService);
    }

    private static OtpVerificationService sharedVerifier(UserService userService, TotpService totpService,
                                                         OcraService ocraService) {
        AccountSecuritySupport support = AccountSecuritySupport.of(userService);
        if (support != null && support.accountLockoutService() != null) {
            AccountLockoutService lockout = support.accountLockoutService();
            return new OtpVerificationService(totpService, ocraService, support.otpUsageStore(), lockout,
                    lockout.clock());
        }
        return OtpVerificationService.inMemory(totpService, ocraService, Clock.systemUTC());
    }

    @Override
    public boolean enforcesAccountProtection() {
        return true;
    }

    @Override
    public Optional<String> generateSecretForUser(Long userId) {
        if (userId == null) {
            return Optional.empty();
        }
        User user = userService.getUserById(userId);
        if (user == null) {
            return Optional.empty();
        }
        String secret = secretGenerator.generateSecret();
        user.setSecret(secret);
        userService.saveUser(user);
        // A new secret always invalidates pending second-factor sessions and previously used OCRA challenges.
        otpVerifier.lockoutService().invalidatePendingSessions(userId);
        otpVerifier.usageStore().resetOcraChallenges(userId);
        return Optional.of(secret);
    }

    @Override
    public Optional<Boolean> validateUserOtp(Long userId, Integer otp) {
        if (userId == null || otp == null) {
            return Optional.empty();
        }
        User user = userService.getUserById(userId);
        if (user == null || user.getSecret() == null) {
            return Optional.empty();
        }
        return Optional.of(otpVerifier.verifyTotp(user, otp).isAccepted());
    }

    @Override
    public Optional<Boolean> validateUserOcra(Long userId, String challenge, String otp) {
        if (userId == null || challenge == null || otp == null) {
            return Optional.empty();
        }
        User user = userService.getUserById(userId);
        if (user == null || user.getSecret() == null) {
            return Optional.empty();
        }
        return Optional.of(otpVerifier.verifyOcra(user, challenge, otp).isAccepted());
    }
}
