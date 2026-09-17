package com.authprovider.service;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public interface OtpProcessor {
    byte[] decodeSecret(String secret);
    int computeTruncatedOtp(byte[] key, byte[] data, int digits) throws NoSuchAlgorithmException, InvalidKeyException;
    int computeTruncatedOtp(byte[] key, byte[] data, int digits, String algorithm) throws NoSuchAlgorithmException, InvalidKeyException;
}
