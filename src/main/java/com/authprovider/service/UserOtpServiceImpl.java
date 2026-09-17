package com.authprovider.service;

import com.authprovider.entity.User;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor(onConstructor_ = @Autowired)
public class UserOtpServiceImpl implements UserOtpService {

    private final UserService userService;
    private final SecretGenerator secretGenerator;
    private final TotpService totpService;
    private final OcraService ocraService;

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
        return Optional.of(totpService.validateOtp(user.getSecret(), otp));
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
        return Optional.of(ocraService.validateOcra(user.getSecret(), challenge, otp));
    }
}
