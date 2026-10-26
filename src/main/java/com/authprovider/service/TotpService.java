package com.authprovider.service;

import java.util.OptionalLong;

public interface TotpService {
    int generateOtp(String secret);
    boolean validateOtp(String secret, int otp);

    /**
     * Returns the TOTP time step (within the accepted clock-drift window) that produced the OTP,
     * allowing callers to reject re-use of an already consumed code.
     */
    default OptionalLong findMatchingTimeStep(String secret, int otp) {
        return OptionalLong.empty();
    }
}
