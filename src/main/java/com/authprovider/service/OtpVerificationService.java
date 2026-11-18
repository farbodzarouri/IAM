package com.authprovider.service;

import com.authprovider.entity.Admin;
import com.authprovider.entity.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.util.OptionalLong;

/**
 * The single second-factor verification path used by every channel (web login, MFA pre-authentication,
 * direct OTP / OCRA validation and in-band RADIUS). For each attempt it
 * <ol>
 *     <li>reserves an attempt against the shared account lockout (refusing locked accounts),</li>
 *     <li>verifies the code,</li>
 *     <li>atomically consumes it in the shared {@link OtpUsageStore} (strictly monotonic TOTP time steps,
 *     single-use OCRA challenges), and</li>
 *     <li>records the failure, or clears the account's failure / lockout state on success.</li>
 * </ol>
 */
@Slf4j
@Service
public class OtpVerificationService {

    private static final long TIME_STEP_MILLIS = 30_000L;

    public enum Result {
        ACCEPTED,
        INVALID,
        REPLAYED,
        LOCKED,
        NOT_ENROLLED;

        public boolean isAccepted() {
            return this == ACCEPTED;
        }
    }

    private final TotpService totpService;
    private final OcraService ocraService;
    private final OtpUsageStore usageStore;
    private final AccountLockoutService lockoutService;
    private final Clock clock;

    @Autowired
    public OtpVerificationService(TotpService totpService, OcraService ocraService, OtpUsageStore usageStore,
                                  AccountLockoutService lockoutService, Clock clock) {
        this.totpService = totpService;
        this.ocraService = ocraService;
        this.clock = clock == null ? Clock.systemUTC() : clock;
        this.usageStore = usageStore == null ? new InMemoryOtpUsageStore() : usageStore;
        this.lockoutService = lockoutService == null ? AccountLockoutService.inMemory(this.clock) : lockoutService;
    }

    /** Node-local verifier (unit tests / embedded use). */
    public static OtpVerificationService inMemory(TotpService totpService, OcraService ocraService, Clock clock) {
        return new OtpVerificationService(totpService, ocraService, null, null, clock);
    }

    public AccountLockoutService lockoutService() {
        return lockoutService;
    }

    public OtpUsageStore usageStore() {
        return usageStore;
    }

    public Result verifyTotp(User user, int otp) {
        return verifyTotp(user, otp, false);
    }

    /**
     * Verifies a TOTP code for a {@link User}. When {@code primaryVerified} is {@code true} (post-password
     * step-2 verification), OTP failures also count against the shared {@code OtpToken} lockout, blocking
     * any linked {@link Admin} sharing that token. Unauthenticated channels ({@code primaryVerified=false})
     * enforce replay protection on the shared token without allowing OTP guessing to lock the admin side.
     */
    public Result verifyTotp(User user, int otp, boolean primaryVerified) {
        if (user == null) {
            return Result.NOT_ENROLLED;
        }
        if (!user.isAccountEnabled()) {
            return Result.LOCKED;
        }
        String secret = user.getSecret();
        if (isBlank(secret)) {
            return Result.NOT_ENROLLED;
        }
        Long userId = user.getId();
        Long tokenId = user.getOtpToken() != null ? user.getOtpToken().getId() : null;
        if (tokenId != null && lockoutService.isTokenLocked(tokenId)) {
            return Result.LOCKED;
        }
        if (!lockoutService.tryBeginAttempt(userId)) {
            return Result.LOCKED;
        }
        if (primaryVerified && tokenId != null && !lockoutService.tryBeginTokenAttempt(tokenId)) {
            lockoutService.confirmFailure(userId);
            return Result.LOCKED;
        }
        OptionalLong step = matchTimeStep(secret, otp);
        if (step.isEmpty()) {
            lockoutService.confirmFailure(userId);
            if (primaryVerified && tokenId != null) {
                lockoutService.confirmTokenFailure(tokenId);
            }
            return Result.INVALID;
        }
        boolean consumed = tokenId != null
                ? usageStore.consumeTokenTimeStep(tokenId, step.getAsLong())
                : (userId == null || usageStore.consumeTimeStep(userId, step.getAsLong()));
        if (!consumed) {
            log.warn("Rejected replayed or out-of-order TOTP for user '{}'", user.getUsername());
            lockoutService.confirmFailure(userId);
            if (primaryVerified && tokenId != null) {
                lockoutService.confirmTokenFailure(tokenId);
            }
            return Result.REPLAYED;
        }
        lockoutService.recordSuccess(userId);
        if (primaryVerified && tokenId != null) {
            lockoutService.recordTokenSuccess(tokenId);
        }
        return Result.ACCEPTED;
    }

    public Result verifyAdminTotp(Admin admin, int otp) {
        if (admin == null) {
            return Result.NOT_ENROLLED;
        }
        if (!admin.isAccountEnabled()) {
            return Result.LOCKED;
        }
        String secret = admin.getEffectiveSecret();
        if (isBlank(secret)) {
            return Result.NOT_ENROLLED;
        }
        Long adminId = admin.getId();
        Long tokenId = admin.getOtpToken() != null ? admin.getOtpToken().getId() : null;
        if (tokenId != null && lockoutService.isTokenLocked(tokenId)) {
            return Result.LOCKED;
        }
        if (!lockoutService.tryBeginAdminAttempt(adminId)) {
            return Result.LOCKED;
        }
        if (tokenId != null && !lockoutService.tryBeginTokenAttempt(tokenId)) {
            lockoutService.confirmAdminFailure(adminId, tokenId);
            return Result.LOCKED;
        }
        OptionalLong step = matchTimeStep(secret, otp);
        if (step.isEmpty()) {
            lockoutService.confirmAdminFailure(adminId, tokenId);
            if (tokenId != null) {
                lockoutService.confirmTokenFailure(tokenId);
            }
            return Result.INVALID;
        }
        boolean consumed = tokenId == null || usageStore.consumeTokenTimeStep(tokenId, step.getAsLong());
        if (!consumed) {
            log.warn("Rejected replayed or out-of-order TOTP for admin '{}'", admin.getUsername());
            lockoutService.confirmAdminFailure(adminId, tokenId);
            if (tokenId != null) {
                lockoutService.confirmTokenFailure(tokenId);
            }
            return Result.REPLAYED;
        }
        lockoutService.recordAdminSuccess(adminId);
        if (tokenId != null) {
            lockoutService.recordTokenSuccess(tokenId);
        }
        return Result.ACCEPTED;
    }

    public Result verifyOcra(User user, String challenge, String response) {
        if (user == null) {
            return Result.NOT_ENROLLED;
        }
        if (!user.isAccountEnabled()) {
            return Result.LOCKED;
        }
        String secret = user.getSecret();
        if (isBlank(secret)) {
            return Result.NOT_ENROLLED;
        }
        Long userId = user.getId();
        Long tokenId = user.getOtpToken() != null ? user.getOtpToken().getId() : null;
        if (tokenId != null && lockoutService.isTokenLocked(tokenId)) {
            return Result.LOCKED;
        }
        if (!lockoutService.tryBeginAttempt(userId)) {
            return Result.LOCKED;
        }
        boolean valid = challenge != null && response != null && ocraService != null
                && ocraService.validateOcra(secret, challenge, response);
        if (!valid) {
            lockoutService.confirmFailure(userId);
            return Result.INVALID;
        }
        boolean consumed = tokenId != null
                ? usageStore.consumeTokenOcraChallenge(tokenId, challenge)
                : (userId == null || usageStore.consumeOcraChallenge(userId, challenge));
        if (!consumed) {
            log.warn("Rejected replayed OCRA response for user '{}'", user.getUsername());
            lockoutService.confirmFailure(userId);
            return Result.REPLAYED;
        }
        lockoutService.recordSuccess(userId);
        return Result.ACCEPTED;
    }

    public OptionalLong matchTimeStep(String secret, int otp) {
        OptionalLong step = otp < 0 || totpService == null ? OptionalLong.empty()
                : totpService.findMatchingTimeStep(secret, otp);
        if (step.isEmpty() && otp >= 0 && totpService != null && totpService.validateOtp(secret, otp)) {
            // TotpService implementations that cannot report the matching step: bind the code to the
            // current step so that it is still single-use.
            step = OptionalLong.of(clock.millis() / TIME_STEP_MILLIS);
        }
        return step;
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
