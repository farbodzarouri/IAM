package com.farbod.service;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class OtpServiceTest {

    private final OtpService otpService = new OtpService();

    @Test
    public void testGenerateSecret() {
        String secret = otpService.generateSecret();
        assertNotNull(secret);
        // Base32 encoding of 20 bytes is 32 characters
        assertEquals(32, secret.length());
        // Base32 only contains A-Z and 2-7
        assertTrue(secret.matches("[A-Z2-7]+"));
    }

    @Test
    public void testGenerateAndValidateOtp() {
        String secret = otpService.generateSecret();
        int otp = otpService.generateOtp(secret);

        assertTrue(otp >= 0 && otp <= 999999);
        assertTrue(otpService.validateOtp(secret, otp));
    }

    @Test
    public void testValidateOtpInvalid() {
        String secret = otpService.generateSecret();
        int otp = otpService.generateOtp(secret);

        assertFalse(otpService.validateOtp(secret, otp + 1));
        assertFalse(otpService.validateOtp(secret, 123456));
    }

    @Test
    public void testOcra() {
        String secret = otpService.generateSecret();
        String challenge = "testChallenge";

        String otp = otpService.generateOcra(secret, challenge);
        assertNotNull(otp);
        assertEquals(6, otp.length());

        assertTrue(otpService.validateOcra(secret, challenge, otp));
        assertFalse(otpService.validateOcra(secret, "wrongChallenge", otp));
    }
}
