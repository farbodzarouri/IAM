package com.authprovider.service;

public interface TotpService {
    int generateOtp(String secret);
    boolean validateOtp(String secret, int otp);
}
