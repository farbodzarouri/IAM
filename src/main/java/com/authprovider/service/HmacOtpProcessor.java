package com.authprovider.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base32;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

@Slf4j
@Component
@RequiredArgsConstructor(onConstructor_ = @Autowired)
public class HmacOtpProcessor implements OtpProcessor {

    private static final String DEFAULT_ALGORITHM = "HmacSHA1";
    private final Base32 base32;

    public HmacOtpProcessor() {
        this(new Base32());
    }

    public byte[] decodeSecret(String secret) {
        return base32.decode(secret);
    }

    public int computeTruncatedOtp(byte[] key, byte[] data, int digits) throws NoSuchAlgorithmException, InvalidKeyException {
        return computeTruncatedOtp(key, data, digits, DEFAULT_ALGORITHM);
    }

    public int computeTruncatedOtp(byte[] key, byte[] data, int digits, String algorithm) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance(algorithm);
        mac.init(new SecretKeySpec(key, algorithm));
        byte[] hash = mac.doFinal(data);

        int offset = hash[hash.length - 1] & 0xF;
        long binary =
                ((hash[offset] & 0x7f) << 24) |
                        ((hash[offset + 1] & 0xff) << 16) |
                        ((hash[offset + 2] & 0xff) << 8) |
                        (hash[offset + 3] & 0xff);

        return (int) (binary % Math.pow(10, digits));
    }
}

