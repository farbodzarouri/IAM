package com.authprovider.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;

@Slf4j
@Primary
@Service
@RequiredArgsConstructor(onConstructor_ = @Autowired)
public class OcraServiceImpl implements OcraService {

    private static final int DEFAULT_DIGITS = 6;

    private final OtpProcessor otpProcessor;

    public OcraServiceImpl() {
        this(new HmacOtpProcessor());
    }

    @Override
    public String generateOcra(String secret, String challenge) {
        try {
            byte[] decodedKey = otpProcessor.decodeSecret(secret);
            byte[] challengeBytes = challenge.getBytes(StandardCharsets.UTF_8);
            int otp = otpProcessor.computeTruncatedOtp(decodedKey, challengeBytes, DEFAULT_DIGITS);
            return String.format("%06d", otp);
        } catch (Exception e) {
            log.error("Failed to generate OCRA OTP", e);
            return null;
        }
    }

    @Override
    public boolean validateOcra(String secret, String challenge, String otp) {
        String generated = generateOcra(secret, challenge);
        return generated != null && generated.equals(otp);
    }
}

