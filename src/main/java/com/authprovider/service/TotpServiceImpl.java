package com.authprovider.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Instant;

@Slf4j
@Primary
@Service
@RequiredArgsConstructor(onConstructor_ = @Autowired)
public class TotpServiceImpl implements TotpService {

    private static final long TIME_STEP = 30000L;
    private static final int DEFAULT_DIGITS = 6;
    private static final int CLOCK_DRIFT_WINDOW = 1;

    private final OtpProcessor otpProcessor;
    private final Clock clock;

    public TotpServiceImpl() {
        this(new HmacOtpProcessor(), Clock.systemUTC());
    }

    public TotpServiceImpl(OtpProcessor otpProcessor) {
        this(otpProcessor, Clock.systemUTC());
    }

    @Override
    public int generateOtp(String secret) {
        long currentBucket = getCurrentBucket();
        return generateOtp(secret, currentBucket);
    }

    @Override
    public boolean validateOtp(String secret, int otp) {
        if (secret == null || secret.isEmpty() || otp < 0) {
            return false;
        }

        long currentBucket = getCurrentBucket();
        for (int i = -CLOCK_DRIFT_WINDOW; i <= CLOCK_DRIFT_WINDOW; i++) {
            long bucket = currentBucket + i;
            if (generateOtp(secret, bucket) == otp) {
                return true;
            }
        }
        return false;
    }

    public int generateOtp(String secret, long counter) {
        try {
            byte[] decodedKey = otpProcessor.decodeSecret(secret);
            byte[] data = new byte[8];
            long time = counter;
            for (int i = 8; i-- > 0; time >>>= 8) {
                data[i] = (byte) time;
            }
            return otpProcessor.computeTruncatedOtp(decodedKey, data, DEFAULT_DIGITS);
        } catch (Exception e) {
            log.error("Failed to generate TOTP", e);
            return -1;
        }
    }

    private long getCurrentBucket() {
        return Instant.now(clock).toEpochMilli() / TIME_STEP;
    }
}


