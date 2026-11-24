package com.authprovider.service;

import com.authprovider.dto.OtpValidationResponse;
import com.authprovider.entity.AuthAuditLog;
import com.authprovider.entity.OtpToken;
import com.authprovider.entity.User;
import com.authprovider.exception.BadRequestException;
import com.authprovider.exception.ConflictException;
import com.authprovider.exception.ResourceNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Direct OTP / OCRA validation and secret management. Validation uses the shared
 * {@link OtpVerificationService}: locked accounts are refused, failures count towards the account-wide
 * lockout, successes clear it, and every accepted code is single-use across all channels.
 */
@Service
public class UserOtpServiceImpl implements UserOtpService {

    private static final Pattern OTP_PATTERN = Pattern.compile("^\\d{1,6}$");

    private final UserService userService;
    private final SecretGenerator secretGenerator;
    private final OtpVerificationService otpVerifier;
    private final AccountResolver<User> accountResolver;
    private final SecurityPolicyService policyService;
    private final AuthAuditService auditService;
    private UserClientAssignmentService assignmentService;

    @Autowired
    public UserOtpServiceImpl(UserService userService,
                              SecretGenerator secretGenerator,
                              TotpService totpService,
                              OcraService ocraService,
                              OtpVerificationService otpVerifier,
                              SecurityPolicyService policyService,
                              AuthAuditService auditService) {
        this.userService = userService;
        this.secretGenerator = secretGenerator;
        this.otpVerifier = otpVerifier != null
                ? otpVerifier
                : OtpVerificationService.inMemory(totpService, ocraService, Clock.systemUTC());
        this.accountResolver = AccountResolver.of(userService);
        this.policyService = policyService == null ? SecurityPolicyService.withDefaults() : policyService;
        this.auditService = auditService == null ? AuthAuditService.noOp() : auditService;
    }

    @Autowired(required = false)
    public void setAssignmentService(UserClientAssignmentService assignmentService) {
        this.assignmentService = assignmentService;
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
        return Optional.of(provisionNewSecret(user));
    }

    @Override
    public String generateSecretForUsername(String username) {
        String trimmed = username == null ? "" : username.trim();
        if (trimmed.isEmpty()) {
            throw new BadRequestException("Username is required");
        }
        AccountResolver.Resolution<User> resolution = accountResolver.resolve(trimmed, policyService.current().isStripRealm());
        if (resolution.status() == AccountResolver.Status.AMBIGUOUS) {
            throw new ConflictException("Ambiguous username: " + trimmed);
        }
        if (!resolution.isFound()) {
            throw new ResourceNotFoundException("User not found: " + trimmed);
        }
        return provisionNewSecret(resolution.user());
    }

    private String provisionNewSecret(User user) {
        String secret = secretGenerator.generateSecret();
        user.setOtpToken(withSecret(user.getOtpToken(), secret));
        User saved = userService.saveUser(user);
        if (saved != null && saved.getOtpToken() != null) {
            user.setOtpToken(saved.getOtpToken());
        }
        Long userId = user.getId();
        if (userId != null) {
            otpVerifier.lockoutService().invalidatePendingSessions(userId);
            otpVerifier.usageStore().resetOcraChallenges(userId);
        }
        if (user.getOtpToken() != null && user.getOtpToken().getId() != null) {
            otpVerifier.usageStore().resetTokenOcraChallenges(user.getOtpToken().getId());
        }
        return secret;
    }

    /**
     * Returns a token carrying {@code secret}: a detached copy of {@code existing} (same id, so the secret of
     * the bound token is replaced when the account is saved) or a new, enabled token when none is bound.
     * OTP secrets are only ever stored in {@link OtpToken}.
     */
    static OtpToken withSecret(OtpToken existing, String secret) {
        if (existing == null) {
            return OtpToken.builder().secret(secret).enabled(true).build();
        }
        return OtpToken.builder()
                .id(existing.getId())
                .person(existing.getPerson())
                .label(existing.getLabel())
                .secret(secret)
                .enabled(existing.isEnabled())
                .createdAt(existing.getCreatedAt())
                .updatedAt(existing.getUpdatedAt())
                .build();
    }

    @Override
    public OtpValidationResponse validateOtpByUsername(String username, String otp) {
        return validateOtpByUsername(username, otp, null);
    }

    @Override
    public OtpValidationResponse validateOtpByUsername(String username, String otp, Long oauthClientId) {
        String trimmedUser = username == null ? "" : username.trim();
        String trimmedOtp = otp == null ? "" : otp.trim();
        if (trimmedUser.isEmpty() || !OTP_PATTERN.matcher(trimmedOtp).matches()) {
            audit(trimmedUser, null, AuthAuditLog.Outcome.FAILURE, "INVALID_REQUEST");
            return OtpValidationResponse.invalidRequest("Username and 6-digit OTP are required");
        }
        AccountResolver.Resolution<User> resolution = accountResolver.resolve(trimmedUser, policyService.current().isStripRealm());
        if (resolution.status() == AccountResolver.Status.AMBIGUOUS) {
            audit(trimmedUser, null, AuthAuditLog.Outcome.FAILURE, "ACCOUNT_CONFLICT");
            return OtpValidationResponse.invalidOtp(trimmedUser);
        }
        if (!resolution.isFound()) {
            audit(trimmedUser, null, AuthAuditLog.Outcome.FAILURE, "UNKNOWN_USER");
            return OtpValidationResponse.invalidOtp(trimmedUser);
        }
        User user = resolution.user();
        if (!isAssigned(user, oauthClientId)) {
            audit(user.getUsername(), user.getId(), AuthAuditLog.Outcome.FAILURE, "CLIENT_NOT_ASSIGNED");
            return OtpValidationResponse.invalidOtp(trimmedUser);
        }
        OtpVerificationService.Result result = otpVerifier.verifyTotp(user, Integer.parseInt(trimmedOtp), false);
        return toResponseAndAudit(user, trimmedUser, result);
    }

    @Override
    public OtpValidationResponse validateOcraByUsername(String username, String challenge, String otp) {
        return validateOcraByUsername(username, challenge, otp, null);
    }

    @Override
    public OtpValidationResponse validateOcraByUsername(String username, String challenge, String otp,
                                                        Long oauthClientId) {
        String trimmedUser = username == null ? "" : username.trim();
        String trimmedChallenge = challenge == null ? "" : challenge.trim();
        String trimmedOtp = otp == null ? "" : otp.trim();
        if (trimmedUser.isEmpty() || trimmedChallenge.isEmpty() || trimmedOtp.isEmpty()) {
            audit(trimmedUser, null, AuthAuditLog.Outcome.FAILURE, "INVALID_REQUEST");
            return OtpValidationResponse.invalidRequest("Username, challenge, and OTP are required");
        }
        AccountResolver.Resolution<User> resolution = accountResolver.resolve(trimmedUser, policyService.current().isStripRealm());
        if (resolution.status() == AccountResolver.Status.AMBIGUOUS) {
            audit(trimmedUser, null, AuthAuditLog.Outcome.FAILURE, "ACCOUNT_CONFLICT");
            return OtpValidationResponse.invalidOtp(trimmedUser);
        }
        if (!resolution.isFound()) {
            audit(trimmedUser, null, AuthAuditLog.Outcome.FAILURE, "UNKNOWN_USER");
            return OtpValidationResponse.invalidOtp(trimmedUser);
        }
        User user = resolution.user();
        if (!isAssigned(user, oauthClientId)) {
            audit(user.getUsername(), user.getId(), AuthAuditLog.Outcome.FAILURE, "CLIENT_NOT_ASSIGNED");
            return OtpValidationResponse.invalidOtp(trimmedUser);
        }
        OtpVerificationService.Result result = otpVerifier.verifyOcra(user, trimmedChallenge, trimmedOtp);
        return toResponseAndAudit(user, trimmedUser, result);
    }

    /**
     * Whether {@code user} may validate through the OAuth 2.0 client {@code oauthClientId}: it requires an
     * enabled assignment. Without a client context ({@code null}) no assignment is required.
     */
    private boolean isAssigned(User user, Long oauthClientId) {
        if (oauthClientId == null) {
            return true;
        }
        if (assignmentService == null || user == null || user.getId() == null) {
            return false;
        }
        return assignmentService.findEnabledOAuthAssignment(user.getId(), oauthClientId).isPresent();
    }

    private OtpValidationResponse toResponseAndAudit(User user, String submittedUsername,
                                                       OtpVerificationService.Result result) {
        String auditUsername = user.getUsername() != null ? user.getUsername() : submittedUsername;
        return switch (result) {
            case ACCEPTED -> {
                audit(auditUsername, user.getId(), AuthAuditLog.Outcome.SUCCESS, "VALID");
                yield OtpValidationResponse.valid(user.getUsername());
            }
            case LOCKED -> {
                audit(auditUsername, user.getId(), AuthAuditLog.Outcome.LOCKED, "LOCKED_OUT");
                yield OtpValidationResponse.locked(user.getUsername());
            }
            case NOT_ENROLLED -> {
                audit(auditUsername, user.getId(), AuthAuditLog.Outcome.FAILURE, "NOT_ENROLLED");
                yield OtpValidationResponse.notEnrolled(user.getUsername());
            }
            case REPLAYED -> {
                audit(auditUsername, user.getId(), AuthAuditLog.Outcome.FAILURE, "OTP_REPLAY");
                yield OtpValidationResponse.invalidOtp(user.getUsername());
            }
            case INVALID -> {
                audit(auditUsername, user.getId(), AuthAuditLog.Outcome.FAILURE, "INVALID_OTP");
                yield OtpValidationResponse.invalidOtp(user.getUsername());
            }
        };
    }

    private void audit(String username, Long userId, AuthAuditLog.Outcome outcome, String reason) {
        auditService.event(AuthAuditLog.Channel.OTP_VALIDATION, outcome)
                .username(username == null || username.isEmpty() ? null : username)
                .userId(userId)
                .reason(reason)
                .log();
    }

    @Override
    public Optional<Boolean> validateUserOtp(Long userId, Integer otp) {
        return validateOtp(userId, otp, false);
    }

    @Override
    public Optional<Boolean> validatePrimaryVerifiedOtp(Long userId, Integer otp) {
        return validateOtp(userId, otp, true);
    }

    private Optional<Boolean> validateOtp(Long userId, Integer otp, boolean primaryVerified) {
        if (userId == null || otp == null) {
            return Optional.empty();
        }
        User user = userService.getUserById(userId);
        if (user == null) {
            return Optional.empty();
        }
        if (!user.isAccountEnabled()) {
            return Optional.of(false);
        }
        if (user.getSecret() == null) {
            return Optional.empty();
        }
        return Optional.of(otpVerifier.verifyTotp(user, otp, primaryVerified).isAccepted());
    }

    @Override
    public Optional<Boolean> validateUserOcra(Long userId, String challenge, String otp) {
        if (userId == null || challenge == null || otp == null) {
            return Optional.empty();
        }
        User user = userService.getUserById(userId);
        if (user == null) {
            return Optional.empty();
        }
        if (!user.isAccountEnabled()) {
            return Optional.of(false);
        }
        if (user.getSecret() == null) {
            return Optional.empty();
        }
        return Optional.of(otpVerifier.verifyOcra(user, challenge, otp).isAccepted());
    }
}
