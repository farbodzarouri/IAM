package com.authprovider.service;

import com.authprovider.config.LdapProperties;
import com.authprovider.dto.LoginRequest;
import com.authprovider.dto.LoginResponse;
import com.authprovider.entity.User;
import com.authprovider.ldap.DirectoryAuthenticationResult;
import com.authprovider.ldap.DirectoryAuthenticator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;
import java.util.regex.Pattern;

@Slf4j
@Service
@RequiredArgsConstructor(onConstructor_ = @Autowired)
public class LoginServiceImpl implements LoginService {

    static final String ISSUER = "IAM";
    static final String SOURCE_DIRECTORY = "LDAP";
    static final String SOURCE_LOCAL = "LOCAL";
    private static final int QR_CODE_SIZE = 200;
    private static final int MAX_USERNAME_LENGTH = 256;
    private static final int MAX_PASSWORD_LENGTH = 1024;
    private static final Pattern OTP_PATTERN = Pattern.compile("^\\d{1,6}$");

    private final LdapProperties ldapProperties;
    private final DirectoryAuthenticator directoryAuthenticator;
    private final UserService userService;
    private final SecretGenerator secretGenerator;
    private final TotpService totpService;
    private final QrCodeGenerator qrCodeGenerator;
    private final Object provisioningLock = new Object();

    @Override
    public LoginResponse login(LoginRequest request) {
        if (request == null) {
            return failure(LoginResponse.Status.INVALID_REQUEST, "Username and password are required");
        }
        String username = normalizeUsername(request.getUsername());
        String password = request.getPassword();
        if (username == null || password == null || password.isEmpty() || password.length() > MAX_PASSWORD_LENGTH) {
            return failure(LoginResponse.Status.INVALID_REQUEST, "Username and password are required");
        }

        if (!ldapProperties.isEnabled()) {
            return authenticateLocal(username, password, request.getOtp());
        }
        return authenticateWithDirectory(username, password, request.getOtp());
    }

    private LoginResponse authenticateWithDirectory(String username, String password, String otp) {
        DirectoryAuthenticationResult result;
        try {
            result = directoryAuthenticator.authenticate(username, password);
        } catch (RuntimeException e) {
            log.error("Directory authentication failed unexpectedly", e);
            result = DirectoryAuthenticationResult.unavailable();
        }
        if (result == null) {
            result = DirectoryAuthenticationResult.unavailable();
        }

        switch (result.status()) {
            case AUTHENTICATED:
                String canonical = result.username() != null ? result.username() : username;
                return completeDirectoryLogin(canonical, otp);
            case USER_NOT_FOUND:
                if (ldapProperties.isFallbackToLocal()) {
                    return authenticateLocal(username, password, otp);
                }
                return invalidCredentials();
            case UNAVAILABLE:
                return failure(LoginResponse.Status.DIRECTORY_UNAVAILABLE, "Directory service is unavailable");
            case INVALID_CREDENTIALS:
            default:
                return invalidCredentials();
        }
    }

    private LoginResponse completeDirectoryLogin(String username, String otp) {
        User user;
        synchronized (provisioningLock) {
            List<User> matches = userService.findAllByUsernameIgnoreCase(username);
            if (matches != null && matches.size() > 1) {
                log.error("Multiple local accounts match directory user {}; refusing to link", username);
                return failure(LoginResponse.Status.ACCOUNT_CONFLICT, "Account cannot be resolved uniquely");
            }
            if (matches == null || matches.isEmpty()) {
                if (!ldapProperties.isAutoProvision()) {
                    return failure(LoginResponse.Status.NOT_PROVISIONED, "Account is not provisioned");
                }
                log.info("Provisioning local account for directory user {}", username);
                return enroll(User.builder().username(username).build(), SOURCE_DIRECTORY);
            }
            user = matches.get(0);
        }
        return verifySecondFactor(user, SOURCE_DIRECTORY, otp);
    }

    private LoginResponse authenticateLocal(String username, String password, String otp) {
        List<User> candidates = userService.findAllByUsernameIgnoreCase(username);
        List<User> matches = candidates == null ? List.of() : candidates.stream()
                .filter(candidate -> username.equals(candidate.getUsername()))
                .toList();
        if (matches.size() != 1) {
            if (matches.size() > 1) {
                log.error("Multiple local accounts share username {}; refusing authentication", username);
            }
            return invalidCredentials();
        }
        User user = matches.get(0);
        if (!passwordMatches(user.getPassword(), password)) {
            return invalidCredentials();
        }
        return verifySecondFactor(user, SOURCE_LOCAL, otp);
    }

    private LoginResponse verifySecondFactor(User user, String source, String otp) {
        if (user.getSecret() == null || user.getSecret().isBlank()) {
            synchronized (provisioningLock) {
                return enroll(user, source);
            }
        }
        if (otp == null || otp.isBlank()) {
            return failure(LoginResponse.Status.OTP_REQUIRED, "One-time password is required");
        }
        String code = otp.trim();
        if (!OTP_PATTERN.matcher(code).matches() || !totpService.validateOtp(user.getSecret(), Integer.parseInt(code))) {
            return failure(LoginResponse.Status.INVALID_OTP, "Invalid one-time password");
        }
        return LoginResponse.builder()
                .status(LoginResponse.Status.AUTHENTICATED)
                .authenticated(true)
                .message("Authentication successful")
                .userId(user.getId())
                .username(user.getUsername())
                .authenticationSource(source)
                .build();
    }

    private LoginResponse enroll(User user, String source) {
        String secret = secretGenerator.generateSecret();
        String otpAuthUri = qrCodeGenerator.generateOtpAuthUrl(ISSUER, encodeLabel(user.getUsername()), secret);
        String qrCode;
        try {
            qrCode = qrCodeGenerator.generateQrCodeImage(otpAuthUri, QR_CODE_SIZE, QR_CODE_SIZE);
        } catch (Exception e) {
            log.error("Failed to generate enrollment QR code for {}", user.getUsername(), e);
            return failure(LoginResponse.Status.ENROLLMENT_FAILED, "Unable to initialize two-factor enrollment");
        }

        User saved;
        try {
            user.setSecret(secret);
            saved = userService.saveUser(user);
        } catch (RuntimeException e) {
            log.error("Failed to persist two-factor secret for {}", user.getUsername(), e);
            return failure(LoginResponse.Status.ENROLLMENT_FAILED, "Unable to initialize two-factor enrollment");
        }
        if (saved == null) {
            saved = user;
        }

        return LoginResponse.builder()
                .status(LoginResponse.Status.ENROLLMENT_REQUIRED)
                .authenticated(false)
                .message("Register the secret with an authenticator app and log in again with the generated code")
                .userId(saved.getId())
                .username(saved.getUsername())
                .authenticationSource(source)
                .secret(secret)
                .otpAuthUri(otpAuthUri)
                .qrCode(qrCode)
                .issuer(ISSUER)
                .build();
    }

    private static String normalizeUsername(String username) {
        if (username == null) {
            return null;
        }
        String trimmed = username.trim();
        if (trimmed.isEmpty() || trimmed.length() > MAX_USERNAME_LENGTH) {
            return null;
        }
        for (int i = 0; i < trimmed.length(); i++) {
            if (Character.isISOControl(trimmed.charAt(i))) {
                return null;
            }
        }
        return trimmed;
    }

    private static boolean passwordMatches(String stored, String provided) {
        if (stored == null || stored.isEmpty()) {
            return false;
        }
        return MessageDigest.isEqual(
                stored.getBytes(StandardCharsets.UTF_8),
                provided.getBytes(StandardCharsets.UTF_8));
    }

    private static String encodeLabel(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }

    private static LoginResponse invalidCredentials() {
        return failure(LoginResponse.Status.INVALID_CREDENTIALS, "Invalid username or password");
    }

    private static LoginResponse failure(LoginResponse.Status status, String message) {
        return LoginResponse.builder()
                .status(status)
                .authenticated(false)
                .message(message)
                .build();
    }
}
