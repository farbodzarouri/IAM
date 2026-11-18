package com.authprovider.service;

import com.authprovider.dto.LoginRequest;
import com.authprovider.dto.LoginResponse;
import com.authprovider.entity.Admin;
import com.authprovider.entity.AuthAuditLog;
import com.authprovider.entity.OtpToken;
import com.authprovider.ldap.DirectoryAuthenticationResult;
import com.authprovider.ldap.DirectoryAuthenticator;
import com.authprovider.ldap.DirectoryConfiguration;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.OptionalLong;
import java.util.regex.Pattern;

@Slf4j
@Service
public class AdminLoginServiceImpl implements AdminLoginService {

    static final String SOURCE_DIRECTORY = "LDAP";
    static final String SOURCE_LOCAL = "LOCAL";
    private static final int MAX_PASSWORD_LENGTH = 1024;
    private static final Pattern OTP_PATTERN = Pattern.compile("^\\d{1,6}$");

    private final DirectoryConfiguration directoryConfiguration;
    private final DirectoryAuthenticator directoryAuthenticator;
    private final AdminService adminService;
    private final PersonService personService;
    private final SecretGenerator secretGenerator;
    private final QrCodeGenerator qrCodeGenerator;
    private final AuthAuditService auditService;
    private final OtpVerificationService otpVerifier;
    private final AccountLockoutService lockoutService;
    private final PasswordService passwordService;
    private final AccountResolver<Admin> adminResolver;
    private final Object provisioningLock = new Object();

    private record PrimaryOutcome(PrimaryStatus status, Admin admin, String source, LoginResponse.Status failureStatus,
                                  String message, boolean locked) {
    }

    @Autowired
    public AdminLoginServiceImpl(DirectoryConfiguration directoryConfiguration,
                                 DirectoryAuthenticator directoryAuthenticator,
                                 AdminService adminService,
                                 PersonService personService,
                                 SecretGenerator secretGenerator,
                                 QrCodeGenerator qrCodeGenerator,
                                 AuthAuditService auditService,
                                 OtpVerificationService otpVerifier,
                                 PasswordService passwordService) {
        this.directoryConfiguration = directoryConfiguration;
        this.directoryAuthenticator = directoryAuthenticator;
        this.adminService = adminService;
        this.personService = personService;
        this.secretGenerator = secretGenerator;
        this.qrCodeGenerator = qrCodeGenerator;
        this.auditService = auditService == null ? AuthAuditService.noOp() : auditService;
        this.otpVerifier = otpVerifier;
        this.lockoutService = otpVerifier.lockoutService();
        this.passwordService = passwordService == null ? PasswordService.withDefaults() : passwordService;
        this.adminResolver = AccountResolver.ofAdmins(adminService);
    }

    @Override
    public LoginResponse login(LoginRequest request) {
        if (request == null) {
            LoginResponse resp = failure(LoginResponse.Status.INVALID_REQUEST, "Username and password are required");
            audit(null, null, null, AuthAuditLog.Outcome.FAILURE, LoginResponse.Status.INVALID_REQUEST.name());
            return resp;
        }
        String username = UsernameNormalizer.sanitizeLoginUsername(request.getUsername());
        String password = request.getPassword();
        if (username == null || password == null || password.isEmpty() || password.length() > MAX_PASSWORD_LENGTH) {
            LoginResponse resp = failure(LoginResponse.Status.INVALID_REQUEST, "Username and password are required");
            audit(request.getUsername(), null, null, AuthAuditLog.Outcome.FAILURE,
                    LoginResponse.Status.INVALID_REQUEST.name());
            return resp;
        }

        PrimaryOutcome primary = authenticatePrimary(username, password);
        if (primary.admin() == null) {
            AuthAuditLog.Outcome outcome = primary.locked() ? AuthAuditLog.Outcome.LOCKED
                    : (primary.status() == PrimaryStatus.DIRECTORY_UNAVAILABLE
                    ? AuthAuditLog.Outcome.ERROR : AuthAuditLog.Outcome.FAILURE);
            String reason = primary.locked() ? "LOCKED_OUT" : primary.failureStatus().name();
            audit(username, null, primary.source(), outcome, reason);
            return failure(primary.failureStatus(), primary.message());
        }

        Admin admin = primary.admin();
        if (primary.status() == PrimaryStatus.AUTHENTICATED_NEEDS_ENROLLMENT) {
            return enrollAndBuildResponse(admin, primary.source());
        }
        return verifyAdminSecondFactor(admin, primary.source(), request.getOtp());
    }

    @Override
    public PrimaryAuthResult verifyPrimary(String username, String password) {
        String normalized = UsernameNormalizer.sanitizeLoginUsername(username);
        if (normalized == null || password == null || password.isEmpty() || password.length() > MAX_PASSWORD_LENGTH) {
            return new PrimaryAuthResult(PrimaryStatus.INVALID_CREDENTIALS, null, null, null);
        }
        PrimaryOutcome primary = authenticatePrimary(normalized, password);
        if (primary.admin() == null) {
            AuthAuditLog.Outcome outcome = primary.locked() ? AuthAuditLog.Outcome.LOCKED
                    : (primary.status() == PrimaryStatus.DIRECTORY_UNAVAILABLE
                    ? AuthAuditLog.Outcome.ERROR : AuthAuditLog.Outcome.FAILURE);
            String reason = primary.locked() ? "LOCKED_OUT" : primary.failureStatus().name();
            audit(normalized, null, primary.source(), outcome, reason);
            return new PrimaryAuthResult(primary.status(), null, null, primary.source());
        }
        return new PrimaryAuthResult(primary.status(), primary.admin().getId(),
                primary.admin().getUsername(), primary.source());
    }

    @Override
    public LoginResponse completeOtp(Long adminId, String source, String otp) {
        Admin admin = adminService.getAdminById(adminId);
        if (admin == null) {
            return failure(LoginResponse.Status.INVALID_CREDENTIALS, "Invalid username or password");
        }
        return verifyAdminSecondFactor(admin, source == null ? SOURCE_LOCAL : source, otp);
    }

    @Override
    public LoginResponse completeEnrollment(Long adminId, String source, String pendingSecret, String otp) {
        Admin admin = adminService.getAdminById(adminId);
        String effectiveSource = source == null ? SOURCE_LOCAL : source;
        if (admin == null) {
            return failure(LoginResponse.Status.INVALID_CREDENTIALS, "Invalid username or password");
        }
        if (isBlocked(admin)) {
            audit(admin.getUsername(), admin.getId(), effectiveSource, AuthAuditLog.Outcome.LOCKED, "LOCKED_OUT");
            return invalidCredentials();
        }
        if (pendingSecret == null || pendingSecret.isBlank() || otp == null || otp.isBlank()) {
            return failure(LoginResponse.Status.INVALID_OTP, "One-time password is required");
        }
        String code = otp.trim();
        if (!OTP_PATTERN.matcher(code).matches()) {
            lockoutService.recordAdminFailure(admin.getId(), tokenIdOf(admin));
            audit(admin.getUsername(), admin.getId(), effectiveSource, AuthAuditLog.Outcome.FAILURE,
                    LoginResponse.Status.INVALID_OTP.name());
            return failure(LoginResponse.Status.INVALID_OTP, "Invalid one-time password");
        }
        int parsedOtp = Integer.parseInt(code);
        OptionalLong matchedStep = otpVerifier.matchTimeStep(pendingSecret, parsedOtp);
        if (matchedStep.isEmpty()) {
            lockoutService.recordAdminFailure(admin.getId(), tokenIdOf(admin));
            audit(admin.getUsername(), admin.getId(), effectiveSource, AuthAuditLog.Outcome.FAILURE,
                    LoginResponse.Status.INVALID_OTP.name());
            return failure(LoginResponse.Status.INVALID_OTP, "Invalid one-time password");
        }
        synchronized (provisioningLock) {
            Admin latest = adminService.getAdminById(adminId);
            if (latest == null) {
                return failure(LoginResponse.Status.INVALID_CREDENTIALS, "Invalid username or password");
            }
            if (latest.getOtpToken() == null) {
                OtpToken token = personService.createToken(latest.getPerson().getId(),
                        latest.getUsername(), pendingSecret);
                latest.setOtpToken(token);
                latest = adminService.saveAdmin(latest);
            }
            Long tokenId = tokenIdOf(latest);
            if (tokenId != null) {
                otpVerifier.usageStore().consumeTokenTimeStep(tokenId, matchedStep.getAsLong());
            }
            lockoutService.recordAdminSuccess(latest.getId());
            if (tokenId != null) {
                lockoutService.recordTokenSuccess(tokenId);
            }
            LoginResponse resp = authenticatedResponse(latest, effectiveSource);
            audit(latest.getUsername(), latest.getId(), effectiveSource, AuthAuditLog.Outcome.SUCCESS,
                    LoginResponse.Status.AUTHENTICATED.name());
            return resp;
        }
    }

    private PrimaryOutcome authenticatePrimary(String username, String password) {
        if (directoryAuthenticator == null || directoryConfiguration == null || !directoryConfiguration.isAdminEnabled()) {
            return authenticateLocal(username, password);
        }
        return authenticateWithDirectory(username, password);
    }

    private PrimaryOutcome authenticateWithDirectory(String username, String password) {
        Admin lockSubject = adminResolver.resolve(username, true).account();
        if (isBlocked(lockSubject)) {
            return lockedOutcome(SOURCE_DIRECTORY);
        }
        DirectoryAuthenticationResult result;
        try {
            result = directoryAuthenticator.authenticateAdmin(username, password);
        } catch (RuntimeException e) {
            log.error("Admin directory authentication failed unexpectedly", e);
            result = DirectoryAuthenticationResult.unavailable();
        }
        if (result == null) {
            result = DirectoryAuthenticationResult.unavailable();
        }
        switch (result.status()) {
            case AUTHENTICATED:
                String canonical = result.username() != null && !result.username().isBlank()
                        ? result.username() : username;
                return resolveOrProvisionDirectoryAdmin(canonical);
            case USER_NOT_FOUND:
                if (directoryConfiguration.isAdminFallbackToLocal(username)) {
                    return authenticateLocal(username, password);
                }
                return invalidPrimary(SOURCE_DIRECTORY);
            case UNAVAILABLE:
                return new PrimaryOutcome(PrimaryStatus.DIRECTORY_UNAVAILABLE, null, SOURCE_DIRECTORY,
                        LoginResponse.Status.DIRECTORY_UNAVAILABLE, "Directory service is unavailable", false);
            case INVALID_CREDENTIALS:
            default:
                if (lockSubject != null) {
                    lockoutService.recordAdminFailure(lockSubject.getId(), tokenIdOf(lockSubject));
                }
                return invalidPrimary(SOURCE_DIRECTORY);
        }
    }

    private PrimaryOutcome resolveOrProvisionDirectoryAdmin(String canonicalUsername) {
        Admin admin;
        synchronized (provisioningLock) {
            AccountResolver.Resolution<Admin> resolution = adminResolver.resolve(canonicalUsername, false);
            if (resolution.status() == AccountResolver.Status.AMBIGUOUS) {
                return new PrimaryOutcome(PrimaryStatus.INVALID_CREDENTIALS, null, SOURCE_DIRECTORY,
                        LoginResponse.Status.ACCOUNT_CONFLICT, "Admin account cannot be resolved uniquely", false);
            }
            admin = resolution.account();
            if (admin == null) {
                if (!directoryConfiguration.isAdminAutoProvision(DirectoryAuthenticationResult.authenticated(canonicalUsername, null))) {
                    return new PrimaryOutcome(PrimaryStatus.NOT_PROVISIONED, null, SOURCE_DIRECTORY,
                            LoginResponse.Status.NOT_PROVISIONED, "Admin account is not provisioned", false);
                }
                log.info("Provisioning local admin account for directory admin {}", canonicalUsername);
                try {
                    admin = adminService.saveAdmin(Admin.builder().username(canonicalUsername).build());
                } catch (RuntimeException e) {
                    Admin concurrent = adminResolver.resolve(canonicalUsername, false).account();
                    if (concurrent == null) {
                        log.error("Failed to provision local admin {}", canonicalUsername, e);
                        return new PrimaryOutcome(PrimaryStatus.INVALID_CREDENTIALS, null, SOURCE_DIRECTORY,
                                LoginResponse.Status.ENROLLMENT_FAILED, "Unable to provision admin account", false);
                    }
                    admin = concurrent;
                }
            }
        }
        if (isBlocked(admin)) {
            return lockedOutcome(SOURCE_DIRECTORY);
        }
        PrimaryStatus nextStatus = admin.getEffectiveSecret() == null
                ? PrimaryStatus.AUTHENTICATED_NEEDS_ENROLLMENT
                : PrimaryStatus.AUTHENTICATED_NEEDS_OTP;
        return new PrimaryOutcome(nextStatus, admin, SOURCE_DIRECTORY, null, null, false);
    }

    private PrimaryOutcome authenticateLocal(String username, String password) {
        AccountResolver.Resolution<Admin> resolution = adminResolver.resolve(username, true);
        if (!resolution.isFound()) {
            passwordService.simulateCheck(password);
            return invalidPrimary(SOURCE_LOCAL);
        }
        Admin admin = resolution.account();
        if (isBlocked(admin)) {
            passwordService.simulateCheck(password);
            return lockedOutcome(SOURCE_LOCAL);
        }
        if (!passwordService.matches(admin.getPassword(), password)) {
            lockoutService.recordAdminFailure(admin.getId(), tokenIdOf(admin));
            return invalidPrimary(SOURCE_LOCAL);
        }
        PrimaryStatus nextStatus = admin.getEffectiveSecret() == null
                ? PrimaryStatus.AUTHENTICATED_NEEDS_ENROLLMENT
                : PrimaryStatus.AUTHENTICATED_NEEDS_OTP;
        return new PrimaryOutcome(nextStatus, admin, SOURCE_LOCAL, null, null, false);
    }

    private LoginResponse verifyAdminSecondFactor(Admin admin, String source, String otp) {
        if (isBlocked(admin)) {
            audit(admin.getUsername(), admin.getId(), source, AuthAuditLog.Outcome.LOCKED, "LOCKED_OUT");
            return invalidCredentials();
        }
        if (admin.getEffectiveSecret() == null) {
            return enrollAndBuildResponse(admin, source);
        }
        if (otp == null || otp.isBlank()) {
            audit(admin.getUsername(), admin.getId(), source, AuthAuditLog.Outcome.FAILURE,
                    LoginResponse.Status.OTP_REQUIRED.name());
            return failure(LoginResponse.Status.OTP_REQUIRED, "One-time password is required");
        }
        String code = otp.trim();
        if (!OTP_PATTERN.matcher(code).matches()) {
            lockoutService.recordAdminFailure(admin.getId(), tokenIdOf(admin));
            if (tokenIdOf(admin) != null) {
                lockoutService.recordTokenFailure(tokenIdOf(admin));
            }
            audit(admin.getUsername(), admin.getId(), source, AuthAuditLog.Outcome.FAILURE,
                    LoginResponse.Status.INVALID_OTP.name());
            return failure(LoginResponse.Status.INVALID_OTP, "Invalid one-time password");
        }
        OtpVerificationService.Result verification = otpVerifier.verifyAdminTotp(admin, Integer.parseInt(code));
        switch (verification) {
            case ACCEPTED:
                audit(admin.getUsername(), admin.getId(), source, AuthAuditLog.Outcome.SUCCESS,
                        LoginResponse.Status.AUTHENTICATED.name());
                return authenticatedResponse(admin, source);
            case LOCKED:
                audit(admin.getUsername(), admin.getId(), source, AuthAuditLog.Outcome.LOCKED, "LOCKED_OUT");
                return invalidCredentials();
            case REPLAYED:
            case INVALID:
            case NOT_ENROLLED:
            default:
                audit(admin.getUsername(), admin.getId(), source, AuthAuditLog.Outcome.FAILURE,
                        LoginResponse.Status.INVALID_OTP.name());
                return failure(LoginResponse.Status.INVALID_OTP, "Invalid one-time password");
        }
    }

    private LoginResponse enrollAndBuildResponse(Admin admin, String source) {
        synchronized (provisioningLock) {
            Admin current = admin.getId() != null ? adminService.getAdminById(admin.getId()) : admin;
            if (current == null) {
                current = admin;
            }
            if (current.getOtpToken() == null) {
                String secret = secretGenerator.generateSecret();
                OtpToken token = personService.createToken(current.getPerson().getId(), current.getUsername(), secret);
                current.setOtpToken(token);
                current = adminService.saveAdmin(current);
            }
            String secret = current.getOtpToken().getSecret();
            OtpProvisioningSupport.ProvisioningQr qr;
            try {
                qr = OtpProvisioningSupport.generate(qrCodeGenerator, current.getUsername(), secret);
            } catch (Exception e) {
                log.error("Failed to generate admin enrollment QR code for {}", current.getUsername(), e);
                return failure(LoginResponse.Status.ENROLLMENT_FAILED, "Unable to initialize two-factor enrollment");
            }
            audit(current.getUsername(), current.getId(), source, AuthAuditLog.Outcome.ENROLLMENT_REQUIRED,
                    LoginResponse.Status.ENROLLMENT_REQUIRED.name());
            return LoginResponse.builder()
                    .status(LoginResponse.Status.ENROLLMENT_REQUIRED)
                    .authenticated(false)
                    .message("Register the secret with an authenticator app and log in again with the generated code")
                    .userId(current.getId())
                    .username(current.getUsername())
                    .authenticationSource(source)
                    .secret(secret)
                    .otpAuthUri(qr.otpAuthUri())
                    .qrCode(qr.qrCode())
                    .issuer(OtpProvisioningSupport.DEFAULT_ISSUER)
                    .build();
        }
    }

    private boolean isBlocked(Admin admin) {
        if (admin == null) {
            return false;
        }
        if (!admin.isAccountEnabled()) {
            return true;
        }
        if (lockoutService.isAdminLocked(admin.getId())) {
            return true;
        }
        Long tokenId = tokenIdOf(admin);
        return tokenId != null && lockoutService.isTokenLocked(tokenId);
    }

    private static Long tokenIdOf(Admin admin) {
        return admin != null && admin.getOtpToken() != null ? admin.getOtpToken().getId() : null;
    }

    private void audit(String username, Long adminId, String source, AuthAuditLog.Outcome outcome, String reason) {
        auditService.event(AuthAuditLog.Channel.ADMIN_LOGIN, outcome)
                .username(username)
                .userId(adminId)
                .source(source)
                .reason(reason)
                .log();
    }

    private static PrimaryOutcome invalidPrimary(String source) {
        return new PrimaryOutcome(PrimaryStatus.INVALID_CREDENTIALS, null, source,
                LoginResponse.Status.INVALID_CREDENTIALS, "Invalid username or password", false);
    }

    private static PrimaryOutcome lockedOutcome(String source) {
        return new PrimaryOutcome(PrimaryStatus.INVALID_CREDENTIALS, null, source,
                LoginResponse.Status.INVALID_CREDENTIALS, "Invalid username or password", true);
    }

    private static LoginResponse authenticatedResponse(Admin admin, String source) {
        return LoginResponse.builder()
                .status(LoginResponse.Status.AUTHENTICATED)
                .authenticated(true)
                .message("Authentication successful")
                .userId(admin.getId())
                .username(admin.getUsername())
                .authenticationSource(source)
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
