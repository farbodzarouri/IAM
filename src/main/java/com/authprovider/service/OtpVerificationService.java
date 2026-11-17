package com.authprovider.service;

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
        if (user == null || isBlank(user.getSecret())) {
            return Result.NOT_ENROLLED;
        }
        Long userId = user.getId();
        if (!lockoutService.tryBeginAttempt(userId)) {
            return Result.LOCKED;
        }
        OptionalLong step = otp < 0 || totpService == null ? OptionalLong.empty()
                : totpService.findMatchingTimeStep(user.getSecret(), otp);
        if (step.isEmpty() && otp >= 0 && totpService != null && totpService.validateOtp(user.getSecret(), otp)) {
            // TotpService implementations that cannot report the matching step: bind the code to the
            // current step so that it is still single-use.
            step = OptionalLong.of(clock.millis() / TIME_STEP_MILLIS);
        }
        if (step.isEmpty()) {
            lockoutService.confirmFailure(userId);
            return Result.INVALID;
        }
        if (userId != null && !usageStore.consumeTimeStep(userId, step.getAsLong())) {
            log.warn("Rejected replayed or out-of-order TOTP for user '{}'", user.getUsername());
            lockoutService.confirmFailure(userId);
            return Result.REPLAYED;
        }
        lockoutService.recordSuccess(userId);
        return Result.ACCEPTED;
    }

    public Result verifyOcra(User user, String challenge, String response) {
        if (user == null || isBlank(user.getSecret())) {
            return Result.NOT_ENROLLED;
        }
        Long userId = user.getId();
        if (!lockoutService.tryBeginAttempt(userId)) {
            return Result.LOCKED;
        }
        boolean valid = challenge != null && response != null && ocraService != null
                && ocraService.validateOcra(user.getSecret(), challenge, response);
        if (!valid) {
            lockoutService.confirmFailure(userId);
            return Result.INVALID;
        }
        if (userId != null && !usageStore.consumeOcraChallenge(userId, challenge)) {
            log.warn("Rejected replayed OCRA response for user '{}'", user.getUsername());
            lockoutService.confirmFailure(userId);
            return Result.REPLAYED;
        }
        lockoutService.recordSuccess(userId);
        return Result.ACCEPTED;
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
