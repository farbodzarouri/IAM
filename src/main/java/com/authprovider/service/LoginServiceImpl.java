package com.authprovider.service;

import com.authprovider.config.LdapProperties;
import com.authprovider.dto.LoginRequest;
import com.authprovider.dto.LoginResponse;
import com.authprovider.entity.AuthAuditLog;
import com.authprovider.entity.AuthMode;
import com.authprovider.entity.User;
import com.authprovider.ldap.DirectoryAuthenticationResult;
import com.authprovider.ldap.DirectoryAuthenticator;
import com.authprovider.ldap.DirectoryConfiguration;
import com.authprovider.ldap.LdapPropertiesDirectoryConfiguration;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.util.regex.Pattern;

@Slf4j
@Service
public class LoginServiceImpl implements LoginService {

    static final String SOURCE_DIRECTORY = "LDAP";
    static final String SOURCE_LOCAL = "LOCAL";
    private static final int OTP_LENGTH = 6;
    private static final int MAX_PASSWORD_LENGTH = 1024;
    private static final Pattern OTP_PATTERN = Pattern.compile("^\\d{1,6}$");

    private final DirectoryConfiguration directoryConfiguration;
    private final DirectoryAuthenticator directoryAuthenticator;
    private final UserService userService;
    private final SecretGenerator secretGenerator;
    private final QrCodeGenerator qrCodeGenerator;
    private final AuthAuditService auditService;
    private final OtpVerificationService otpVerifier;
    private final AccountLockoutService lockoutService;
    private final SecurityPolicyService policyService;
    private final PasswordService passwordService;
    /** Resolves the account that authenticates (local login / directory linking / provisioning). */
    private final AccountResolver<User> accountResolver;
    /** Resolves the account a request applies to for lockout purposes, before any credential is checked. */
    private final AccountResolver<User> lockoutSubjectResolver;
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
        this(new LdapPropertiesDirectoryConfiguration(ldapProperties),
                directoryAuthenticator,
                userService,
                secretGenerator,
                qrCodeGenerator,
                AuthAuditService.noOp(),
                OtpVerificationService.inMemory(totpService, null, Clock.systemUTC()),
                SecurityPolicyService.withDefaults(),
                PasswordService.withDefaults());
    }

    @Autowired
    public LoginServiceImpl(DirectoryConfiguration directoryConfiguration,
                            DirectoryAuthenticator directoryAuthenticator,
                            UserService userService,
                            SecretGenerator secretGenerator,
                            QrCodeGenerator qrCodeGenerator,
                            AuthAuditService auditService,
                            OtpVerificationService otpVerifier,
                            SecurityPolicyService policyService,
                            PasswordService passwordService) {
        this.directoryConfiguration = directoryConfiguration;
        this.directoryAuthenticator = directoryAuthenticator;
        this.userService = userService;
        this.secretGenerator = secretGenerator;
        this.qrCodeGenerator = qrCodeGenerator;
        this.auditService = auditService == null ? AuthAuditService.noOp() : auditService;
        this.otpVerifier = otpVerifier == null ? OtpVerificationService.inMemory(null, null, Clock.systemUTC()) : otpVerifier;
        this.lockoutService = this.otpVerifier.lockoutService();
        this.policyService = policyService == null ? SecurityPolicyService.withDefaults() : policyService;
        this.passwordService = passwordService == null ? PasswordService.withDefaults() : passwordService;
        this.accountResolver = new AccountResolver<>(userService::findAllByUsernameIgnoreCase, null);
        this.lockoutSubjectResolver = new AccountResolver<>(userService::findByUsernameIgnoreCase, null);
    }

    @Override
    public LoginResponse login(LoginRequest request) {
        return login(request, null);
    }

    @Override
    public LoginResponse login(LoginRequest request, AuthMode clientAuthMode) {
        Outcome outcome = doLogin(request, clientAuthMode);
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

    private Outcome doLogin(LoginRequest request, AuthMode clientMode) {
        if (request == null) {
            return result(failure(LoginResponse.Status.INVALID_REQUEST, "Username and password are required"));
        }
        String username = UsernameNormalizer.sanitizeLoginUsername(request.getUsername());
        String password = request.getPassword();
        if (username == null || (password != null && password.length() > MAX_PASSWORD_LENGTH)) {
            return result(failure(LoginResponse.Status.INVALID_REQUEST, "Username and password are required"));
        }
        if (password == null || password.isEmpty()) {
            AccountResolver.Resolution<User> resolution = accountResolver.resolve(username, isStripRealm());
            if (resolution.isFound() && effectiveAuthMode(resolution.user(), clientMode) == AuthMode.OTP_ONLY) {
                return authenticateOtpOnly(resolution.user(), request.getOtp());
            }
            if (!resolution.isFound() && resolution.status() != AccountResolver.Status.AMBIGUOUS
                    && baseAuthMode(clientMode) == AuthMode.OTP_ONLY) {
                return result(invalidCredentials());
            }
            if (resolution.status() == AccountResolver.Status.AMBIGUOUS) {
                return result(invalidCredentials());
            }
            return result(failure(LoginResponse.Status.INVALID_REQUEST, "Username and password are required"));
        }

        if (directoryAuthenticator == null || !directoryConfiguration.isEnabled()) {
            return authenticateLocal(username, password, request.getOtp(), clientMode);
        }
        return authenticateWithDirectory(username, password, request.getOtp(), clientMode);
    }

    private Outcome authenticateWithDirectory(String username, String password, String otp, AuthMode clientMode) {
        // Lockouts are enforced before the directory bind so that a locked account cannot be used to
        // probe (or lock out) the directory account.
        User lockSubject = lockoutSubjectResolver.resolve(username, isStripRealm()).user();
        if (isBlocked(lockSubject)) {
            return locked(lockSubject);
        }
        AuthMode preMode = effectiveAuthMode(lockSubject, clientMode);
        if (preMode == AuthMode.OTP_ONLY) {
            return authenticateOtpOnly(lockSubject, otp);
        }

        String bindPassword = password;
        String effectiveOtp = otp;
        if (preMode == AuthMode.PASSWORD_AND_OTP_INLINE && (otp == null || otp.isBlank())) {
            if (!hasTrailingSixDigits(password) || password.length() <= OTP_LENGTH) {
                if (lockSubject != null) {
                    lockoutService.recordFailure(lockSubject.getId());
                }
                return result(invalidCredentials());
            }
            bindPassword = password.substring(0, password.length() - OTP_LENGTH);
            effectiveOtp = password.substring(password.length() - OTP_LENGTH);
        }

        DirectoryAuthenticationResult result;
        try {
            result = directoryAuthenticator.authenticate(username, bindPassword);
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
                return completeDirectoryLogin(canonical, effectiveOtp, directoryConfiguration.isAutoProvision(result),
                        clientMode);
            case USER_NOT_FOUND:
                if (directoryConfiguration.isFallbackToLocal(username)) {
                    return authenticateLocal(username, password, otp, clientMode);
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

    private Outcome completeDirectoryLogin(String username, String otp, boolean autoProvision, AuthMode clientMode) {
        User user;
        synchronized (provisioningLock) {
            // The directory's canonical name is authoritative: it is linked as is (no realm stripping),
            // exactly like RADIUS links directory identities (see PrimaryCredentialVerifier#findLinkedAccount).
            AccountResolver.Resolution<User> resolution = accountResolver.resolve(username, false);
            if (resolution.status() == AccountResolver.Status.AMBIGUOUS) {
                log.error("Multiple local accounts match directory user {}; refusing to link", username);
                return result(failure(LoginResponse.Status.ACCOUNT_CONFLICT, "Account cannot be resolved uniquely"));
            }
            if (!resolution.isFound()) {
                if (!autoProvision) {
                    return result(failure(LoginResponse.Status.NOT_PROVISIONED, "Account is not provisioned"));
                }
                log.info("Provisioning local account for directory user {}", username);
                if (baseAuthMode(clientMode) == AuthMode.PASSWORD_ONLY) {
                    User created = provisionWithoutSecret(username);
                    if (created != null) {
                        lockoutService.recordSuccess(created.getId());
                        return authenticatedOutcome(created, SOURCE_DIRECTORY);
                    }
                    resolution = accountResolver.resolve(username, false);
                    if (!resolution.isFound()) {
                        return result(failure(LoginResponse.Status.ENROLLMENT_FAILED, "Unable to provision account"));
                    }
                } else {
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
            }
            user = resolution.user();
        }
        if (isBlocked(user)) {
            return locked(user);
        }
        AuthMode mode = effectiveAuthMode(user, clientMode);
        if (mode == AuthMode.PASSWORD_ONLY) {
            lockoutService.recordSuccess(user.getId());
            return authenticatedOutcome(user, SOURCE_DIRECTORY);
        }
        if (mode == AuthMode.OTP_ONLY) {
            return authenticateOtpOnly(user, otp);
        }
        return verifySecondFactor(user, SOURCE_DIRECTORY, otp);
    }

    private User provisionWithoutSecret(String username) {
        try {
            return userService.saveUser(User.builder().username(username).build());
        } catch (RuntimeException e) {
            log.warn("Unable to auto-provision password-only user '{}': {}", username, e.getMessage());
            return null;
        }
    }

    private Outcome authenticateLocal(String username, String password, String otp, AuthMode clientMode) {
        AccountResolver.Resolution<User> resolution = accountResolver.resolve(username, isStripRealm());
        if (!resolution.isFound()) {
            if (resolution.status() == AccountResolver.Status.AMBIGUOUS) {
                log.error("Multiple local accounts share username {}; refusing authentication", username);
            }
            passwordService.simulateCheck(password);
            return result(invalidCredentials());
        }
        User user = resolution.user();
        if (isBlocked(user)) {
            passwordService.simulateCheck(password);
            return locked(user);
        }
        AuthMode mode = effectiveAuthMode(user, clientMode);
        if (mode == AuthMode.OTP_ONLY) {
            return authenticateOtpOnly(user, otp);
        }

        String candidatePassword = password;
        String effectiveOtp = otp;
        if (mode == AuthMode.PASSWORD_AND_OTP_INLINE && (otp == null || otp.isBlank())) {
            if (!hasTrailingSixDigits(password) || password.length() <= OTP_LENGTH) {
                lockoutService.recordFailure(user.getId());
                return result(invalidCredentials());
            }
            candidatePassword = password.substring(0, password.length() - OTP_LENGTH);
            effectiveOtp = password.substring(password.length() - OTP_LENGTH);
        }

        if (!passwordService.matches(user.getPassword(), candidatePassword)) {
            lockoutService.recordFailure(user.getId());
            return result(invalidCredentials());
        }
        if (mode == AuthMode.PASSWORD_ONLY) {
            lockoutService.recordSuccess(user.getId());
            return authenticatedOutcome(user, SOURCE_LOCAL);
        }
        return verifySecondFactor(user, SOURCE_LOCAL, effectiveOtp);
    }

    private Outcome authenticateOtpOnly(User user, String otp) {
        if (user == null) {
            return result(invalidCredentials());
        }
        if (isBlocked(user)) {
            return locked(user);
        }
        if (user.getSecret() == null || user.getSecret().isBlank()) {
            return result(failure(LoginResponse.Status.NOT_PROVISIONED, "OTP token is not enrolled"));
        }
        if (otp == null || otp.isBlank()) {
            return result(failure(LoginResponse.Status.OTP_REQUIRED, "One-time password is required"));
        }
        String code = otp.trim();
        if (!OTP_PATTERN.matcher(code).matches()) {
            // OTP-only login has no verified first factor: record account lockout only, never token lockout.
            lockoutService.recordFailure(user.getId());
            return result(failure(LoginResponse.Status.INVALID_OTP, "Invalid one-time password"));
        }
        OtpVerificationService.Result verification = otpVerifier.verifyTotp(user, Integer.parseInt(code), false);
        return switch (verification) {
            case ACCEPTED -> authenticatedOutcome(user, SOURCE_LOCAL);
            case LOCKED -> locked(user);
            case NOT_ENROLLED -> result(failure(LoginResponse.Status.NOT_PROVISIONED, "OTP token is not enrolled"));
            case REPLAYED -> {
                log.warn("Rejected replayed TOTP for user {}", user.getUsername());
                yield result(failure(LoginResponse.Status.INVALID_OTP, "Invalid one-time password"));
            }
            case INVALID -> result(failure(LoginResponse.Status.INVALID_OTP, "Invalid one-time password"));
        };
    }

    private Outcome verifySecondFactor(User user, String source, String otp) {
        if (isBlocked(user)) {
            return locked(user);
        }
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
            if (isBlocked(user)) {
                return locked(user);
            }
            lockoutService.recordFailure(user.getId());
            if (user.getOtpToken() != null && user.getOtpToken().getId() != null) {
                lockoutService.recordTokenFailure(user.getOtpToken().getId());
            }
            return result(failure(LoginResponse.Status.INVALID_OTP, "Invalid one-time password"));
        }
        OtpVerificationService.Result verification = otpVerifier.verifyTotp(user, Integer.parseInt(code), true);
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
        return authenticatedOutcome(user, source);
    }

    /**
     * Resolves the effective mode like RADIUS clients: an account override wins over the calling OAuth 2.0
     * client's override, which wins over the policy default. A strict {@code PASSWORD_AND_OTP} account may
     * still submit its OTP inline when the client requires {@code PASSWORD_AND_OTP_INLINE}.
     */
    private AuthMode effectiveAuthMode(User user, AuthMode clientMode) {
        AuthMode base = baseAuthMode(clientMode);
        if (user != null && user.getAuthMode() != null) {
            if (user.getAuthMode() == AuthMode.PASSWORD_AND_OTP && clientMode == AuthMode.PASSWORD_AND_OTP_INLINE) {
                return AuthMode.PASSWORD_AND_OTP_INLINE;
            }
            return user.getAuthMode();
        }
        return base;
    }

    private AuthMode baseAuthMode(AuthMode clientMode) {
        return clientMode != null ? clientMode : policyDefaultAuthMode();
    }

    private AuthMode policyDefaultAuthMode() {
        return policyService.current().getDefaultAuthMode();
    }

    private boolean isStripRealm() {
        return policyService.current().isStripRealm();
    }

    private static boolean hasTrailingSixDigits(String value) {
        if (value == null || value.length() < OTP_LENGTH) {
            return false;
        }
        for (int i = value.length() - OTP_LENGTH; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c < '0' || c > '9') {
                return false;
            }
        }
        return true;
    }

    private static Outcome authenticatedOutcome(User user, String source) {
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
            try {
                lockoutService.invalidatePendingSessions(response.getUserId());
                otpVerifier.usageStore().resetOcraChallenges(response.getUserId());
                if (user.getOtpToken() != null && user.getOtpToken().getId() != null) {
                    otpVerifier.usageStore().resetTokenOcraChallenges(user.getOtpToken().getId());
                }
            } catch (RuntimeException e) {
                log.error("Unable to invalidate pending sessions after enrollment of {}", user.getUsername(), e);
            }
        }
        return result(response);
    }

    private boolean isBlocked(User user) {
        if (user == null) {
            return false;
        }
        if (!user.isAccountEnabled()) {
            return true;
        }
        if (lockoutService.isLocked(user.getId())) {
            return true;
        }
        return user.getOtpToken() != null && lockoutService.isTokenLocked(user.getOtpToken().getId());
    }

    private static Outcome result(LoginResponse response) {
        return new Outcome(response, false);
    }

    private static Outcome locked(User user) {
        log.warn("Web login refused for locked-out account '{}'", user.getUsername());
        return new Outcome(invalidCredentials(), true);
    }

    private LoginResponse enroll(User user, String source) {
        String secret = secretGenerator.generateSecret();
        OtpProvisioningSupport.ProvisioningQr qr;
        try {
            qr = OtpProvisioningSupport.generate(qrCodeGenerator, user.getUsername(), secret);
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
                .otpAuthUri(qr.otpAuthUri())
                .qrCode(qr.qrCode())
                .issuer(OtpProvisioningSupport.DEFAULT_ISSUER)
                .build();
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
