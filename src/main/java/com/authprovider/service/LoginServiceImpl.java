package com.authprovider.service;

import com.authprovider.config.LdapProperties;
import com.authprovider.dto.LoginRequest;
import com.authprovider.dto.LoginResponse;
import com.authprovider.entity.AuthAuditLog;
import com.authprovider.entity.User;
import com.authprovider.ldap.DirectoryAuthenticationResult;
import com.authprovider.ldap.DirectoryAuthenticator;
import com.authprovider.ldap.DirectoryConfiguration;
import com.authprovider.ldap.LdapPropertiesDirectoryConfiguration;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.util.regex.Pattern;

@Slf4j
@Service
public class LoginServiceImpl implements LoginService {

    static final String ISSUER = "IAM";
    static final String SOURCE_DIRECTORY = "LDAP";
    static final String SOURCE_LOCAL = "LOCAL";
    private static final int QR_CODE_SIZE = 200;
    private static final int MAX_USERNAME_LENGTH = 256;
    private static final int MAX_PASSWORD_LENGTH = 1024;
    private static final Pattern OTP_PATTERN = Pattern.compile("^\\d{1,6}$");
    private static final String DUMMY_HASH = new BCryptPasswordEncoder().encode("\u0000dummy-password\u0000");

    private final DirectoryConfiguration directoryConfiguration;
    private final DirectoryAuthenticator directoryAuthenticator;
    private final UserService userService;
    private final SecretGenerator secretGenerator;
    private final TotpService totpService;
    private final QrCodeGenerator qrCodeGenerator;
    private final AuthAuditService auditService;
    private final OtpVerificationService otpVerifier;
    private final AccountLockoutService lockoutService;
    /** Resolves the account that authenticates (local login / directory linking / provisioning). */
    private final AccountResolver accountResolver;
    /** Resolves the account a request applies to for lockout purposes, before any credential is checked. */
    private final AccountResolver lockoutSubjectResolver;
    private final BCryptPasswordEncoder bcryptEncoder = new BCryptPasswordEncoder();
    private final Object provisioningLock = new Object();

    /** Internal result carrying the audit details next to the API response. */
    private record Outcome(LoginResponse response, boolean locked) {
    }

    public LoginServiceImpl(LdapProperties ldapProperties,
                            DirectoryAuthenticator directoryAuthenticator,
                            UserService userService,
                            SecretGenerator secretGenerator,
                            TotpService totpService,
                            QrCodeGenerator qrCodeGenerator) {
        this(new LdapPropertiesDirectoryConfiguration(ldapProperties), directoryAuthenticator, userService,
                secretGenerator, totpService, qrCodeGenerator, AuthAuditService.noOp());
    }

    public LoginServiceImpl(DirectoryConfiguration directoryConfiguration,
                            DirectoryAuthenticator directoryAuthenticator,
                            UserService userService,
                            SecretGenerator secretGenerator,
                            TotpService totpService,
                            QrCodeGenerator qrCodeGenerator,
                            AuthAuditService auditService) {
        this(directoryConfiguration, directoryAuthenticator, userService, secretGenerator, totpService,
                qrCodeGenerator, auditService, sharedVerifier(userService, totpService));
    }

    @Autowired
    public LoginServiceImpl(DirectoryConfiguration directoryConfiguration,
                            DirectoryAuthenticator directoryAuthenticator,
                            UserService userService,
                            SecretGenerator secretGenerator,
                            TotpService totpService,
                            QrCodeGenerator qrCodeGenerator,
                            AuthAuditService auditService,
                            OtpVerificationService otpVerifier) {
        this.directoryConfiguration = directoryConfiguration;
        this.directoryAuthenticator = directoryAuthenticator;
        this.userService = userService;
        this.secretGenerator = secretGenerator;
        this.totpService = totpService;
        this.qrCodeGenerator = qrCodeGenerator;
        this.auditService = auditService == null ? AuthAuditService.noOp() : auditService;
        this.otpVerifier = otpVerifier == null ? sharedVerifier(userService, totpService) : otpVerifier;
        this.lockoutService = this.otpVerifier.lockoutService();
        this.accountResolver = new AccountResolver(userService::findAllByUsernameIgnoreCase, null);
        this.lockoutSubjectResolver = new AccountResolver(userService::findByUsernameIgnoreCase, null);
    }

    private static OtpVerificationService sharedVerifier(UserService userService, TotpService totpService) {
        AccountSecuritySupport support = AccountSecuritySupport.of(userService);
        if (support != null && support.accountLockoutService() != null) {
            AccountLockoutService lockout = support.accountLockoutService();
            return new OtpVerificationService(totpService, null, support.otpUsageStore(), lockout, lockout.clock());
        }
        return OtpVerificationService.inMemory(totpService, null, Clock.systemUTC());
    }

    @Override
    public LoginResponse login(LoginRequest request) {
        Outcome outcome = doLogin(request);
        audit(request, outcome);
        return outcome.response();
    }

    private void audit(LoginRequest request, Outcome result) {
        LoginResponse response = result == null ? null : result.response();
        if (response == null) {
            return;
        }
        LoginResponse.Status status = response.getStatus();
        AuthAuditLog.Outcome outcome;
        if (result.locked()) {
            outcome = AuthAuditLog.Outcome.LOCKED;
        } else if (status == LoginResponse.Status.AUTHENTICATED) {
            outcome = AuthAuditLog.Outcome.SUCCESS;
        } else if (status == LoginResponse.Status.ENROLLMENT_REQUIRED) {
            outcome = AuthAuditLog.Outcome.ENROLLMENT_REQUIRED;
        } else if (status == LoginResponse.Status.DIRECTORY_UNAVAILABLE || status == LoginResponse.Status.ENROLLMENT_FAILED) {
            outcome = AuthAuditLog.Outcome.ERROR;
        } else {
            outcome = AuthAuditLog.Outcome.FAILURE;
        }
        String username = response.getUsername() != null ? response.getUsername()
                : request == null ? null : request.getUsername();
        auditService.event(AuthAuditLog.Channel.WEB_LOGIN, outcome)
                .username(username)
                .userId(response.getUserId())
                .reason(result.locked() ? "LOCKED_OUT" : status == null ? null : status.name())
                .source(response.getAuthenticationSource())
                .log();
    }

    private Outcome doLogin(LoginRequest request) {
        if (request == null) {
            return result(failure(LoginResponse.Status.INVALID_REQUEST, "Username and password are required"));
        }
        String username = normalizeUsername(request.getUsername());
        String password = request.getPassword();
        if (username == null || password == null || password.isEmpty() || password.length() > MAX_PASSWORD_LENGTH) {
            return result(failure(LoginResponse.Status.INVALID_REQUEST, "Username and password are required"));
        }

        if (directoryAuthenticator == null || !directoryConfiguration.isEnabled()) {
            return authenticateLocal(username, password, request.getOtp());
        }
        return authenticateWithDirectory(username, password, request.getOtp());
    }

    private Outcome authenticateWithDirectory(String username, String password, String otp) {
        // Lockouts are enforced before the directory bind so that a locked account cannot be used to
        // probe (or lock out) the directory account.
        User lockSubject = lockoutSubjectResolver.resolve(username, true).user();
        if (lockSubject != null && lockoutService.isLocked(lockSubject.getId())) {
            return locked(lockSubject);
        }
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
                String canonical = result.username() != null && !result.username().isBlank()
                        ? result.username() : username;
                return completeDirectoryLogin(canonical, otp, directoryConfiguration.isAutoProvision(result));
            case USER_NOT_FOUND:
                if (directoryConfiguration.isFallbackToLocal(username)) {
                    return authenticateLocal(username, password, otp);
                }
                return result(invalidCredentials());
            case UNAVAILABLE:
                return result(failure(LoginResponse.Status.DIRECTORY_UNAVAILABLE, "Directory service is unavailable"));
            case INVALID_CREDENTIALS:
            default:
                if (lockSubject != null) {
                    lockoutService.recordFailure(lockSubject.getId());
                }
                return result(invalidCredentials());
        }
    }

    private Outcome completeDirectoryLogin(String username, String otp, boolean autoProvision) {
        User user;
        synchronized (provisioningLock) {
            // The directory's canonical name is authoritative: it is linked as is (no realm stripping),
            // exactly like RADIUS links directory identities (see PrimaryCredentialVerifier#findLinkedAccount).
            AccountResolver.Resolution resolution = accountResolver.resolve(username, false);
            if (resolution.status() == AccountResolver.Status.AMBIGUOUS) {
                log.error("Multiple local accounts match directory user {}; refusing to link", username);
                return result(failure(LoginResponse.Status.ACCOUNT_CONFLICT, "Account cannot be resolved uniquely"));
            }
            if (!resolution.isFound()) {
                if (!autoProvision) {
                    return result(failure(LoginResponse.Status.NOT_PROVISIONED, "Account is not provisioned"));
                }
                log.info("Provisioning local account for directory user {}", username);
                Outcome provisioned = enrollOutcome(User.builder().username(username).build(), SOURCE_DIRECTORY);
                if (provisioned.response().getStatus() != LoginResponse.Status.ENROLLMENT_FAILED) {
                    return provisioned;
                }
                // Another node may have provisioned the same account concurrently: link to it instead.
                resolution = accountResolver.resolve(username, false);
                if (!resolution.isFound()) {
                    return provisioned;
                }
            }
            user = resolution.user();
        }
        if (lockoutService.isLocked(user.getId())) {
            return locked(user);
        }
        return verifySecondFactor(user, SOURCE_DIRECTORY, otp);
    }

    private Outcome authenticateLocal(String username, String password, String otp) {
        AccountResolver.Resolution resolution = accountResolver.resolve(username, true);
        if (!resolution.isFound()) {
            if (resolution.status() == AccountResolver.Status.AMBIGUOUS) {
                log.error("Multiple local accounts share username {}; refusing authentication", username);
            }
            simulatePasswordCheck(password);
            return result(invalidCredentials());
        }
        User user = resolution.user();
        if (lockoutService.isLocked(user.getId())) {
            simulatePasswordCheck(password);
            return locked(user);
        }
        if (!passwordMatches(user.getPassword(), password)) {
            lockoutService.recordFailure(user.getId());
            return result(invalidCredentials());
        }
        return verifySecondFactor(user, SOURCE_LOCAL, otp);
    }

    private Outcome verifySecondFactor(User user, String source, String otp) {
        if (user.getSecret() == null || user.getSecret().isBlank()) {
            synchronized (provisioningLock) {
                return enrollOutcome(user, source);
            }
        }
        if (otp == null || otp.isBlank()) {
            return result(failure(LoginResponse.Status.OTP_REQUIRED, "One-time password is required"));
        }
        String code = otp.trim();
        if (!OTP_PATTERN.matcher(code).matches()) {
            if (lockoutService.isLocked(user.getId())) {
                return locked(user);
            }
            lockoutService.recordFailure(user.getId());
            return result(failure(LoginResponse.Status.INVALID_OTP, "Invalid one-time password"));
        }
        OtpVerificationService.Result verification = otpVerifier.verifyTotp(user, Integer.parseInt(code));
        switch (verification) {
            case ACCEPTED:
                break;
            case LOCKED:
                return locked(user);
            case REPLAYED:
                log.warn("Rejected replayed TOTP for user {}", user.getUsername());
                return result(failure(LoginResponse.Status.INVALID_OTP, "Invalid one-time password"));
            case INVALID:
            case NOT_ENROLLED:
            default:
                return result(failure(LoginResponse.Status.INVALID_OTP, "Invalid one-time password"));
        }
        return result(LoginResponse.builder()
                .status(LoginResponse.Status.AUTHENTICATED)
                .authenticated(true)
                .message("Authentication successful")
                .userId(user.getId())
                .username(user.getUsername())
                .authenticationSource(source)
                .build());
    }

    /**
     * Clears all TOTP replay state used by this service (maintenance / test hook). In a cluster this
     * affects the shared replay state of every node.
     */
    public void resetReplayState() {
        otpVerifier.usageStore().clear();
    }

    private Outcome enrollOutcome(User user, String source) {
        LoginResponse response = enroll(user, source);
        if (response.getStatus() == LoginResponse.Status.ENROLLMENT_REQUIRED && response.getUserId() != null) {
            // A new secret invalidates anything pending for the account.
            try {
                lockoutService.invalidatePendingSessions(response.getUserId());
                otpVerifier.usageStore().resetOcraChallenges(response.getUserId());
            } catch (RuntimeException e) {
                log.error("Unable to invalidate pending sessions after enrollment of {}", user.getUsername(), e);
            }
        }
        return result(response);
    }

    private static Outcome result(LoginResponse response) {
        return new Outcome(response, false);
    }

    /**
     * Locked accounts receive the same response as invalid credentials (no account state disclosure and
     * no change of the API contract); the audit log records the lockout.
     */
    private static Outcome locked(User user) {
        log.warn("Web login refused for locked-out account '{}'", user.getUsername());
        return new Outcome(invalidCredentials(), true);
    }

    private void simulatePasswordCheck(String password) {
        bcryptEncoder.matches(password, DUMMY_HASH);
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

    private boolean passwordMatches(String stored, String provided) {
        if (stored == null || stored.isEmpty() || provided == null) {
            return false;
        }
        if (stored.startsWith("$2a$") || stored.startsWith("$2b$") || stored.startsWith("$2y$")) {
            return bcryptEncoder.matches(provided, stored);
        }
        if (stored.startsWith("{bcrypt}")) {
            return bcryptEncoder.matches(provided, stored.substring("{bcrypt}".length()));
        }
        if (stored.startsWith("{noop}")) {
            return constantTimeEquals(provided, stored.substring("{noop}".length()));
        }
        return constantTimeEquals(provided, stored);
    }

    private static boolean constantTimeEquals(String a, String b) {
        return MessageDigest.isEqual(
                a.getBytes(StandardCharsets.UTF_8),
                b.getBytes(StandardCharsets.UTF_8));
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
