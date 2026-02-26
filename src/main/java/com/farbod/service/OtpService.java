package com.farbod.service;

import org.apache.commons.codec.binary.Base32;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;

@Service
public class OtpService {

    private static final int SECRET_SIZE = 20; // 160 bits
    private static final long TIME_STEP = 30000; // 30 seconds

    public String generateSecret() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[SECRET_SIZE];
        random.nextBytes(bytes);
        Base32 base32 = new Base32();
        return base32.encodeToString(bytes);
    }

    public boolean validateOtp(String secret, int otp) {
        if (secret == null || secret.isEmpty()) {
            return false;
        }

        long currentTime = Instant.now().toEpochMilli();
        long currentBucket = currentTime / TIME_STEP;

        // Check current bucket and surrounding buckets for clock drift
        for (int i = -1; i <= 1; i++) {
            long bucket = currentBucket + i;
            if (generateOtp(secret, bucket) == otp) {
                return true;
            }
        }
        return false;
    }

    public int generateOtp(String secret) {
        long currentTime = Instant.now().toEpochMilli();
        long currentBucket = currentTime / TIME_STEP;
        return generateOtp(secret, currentBucket);
    }

    private int generateOtp(String secret, long counter) {
        try {
            Base32 base32 = new Base32();
            byte[] decodedKey = base32.decode(secret);
            return generateTOTP(decodedKey, counter, 6);
        } catch (Exception e) {
            e.printStackTrace();
            return -1;
        }
    }

    // Based on RFC 6238 and RFC 4226
    private int generateTOTP(byte[] key, long time, int returnDigits) throws NoSuchAlgorithmException, InvalidKeyException {
        String algorithm = "HmacSHA1";

        // The time parameter is the counter value (T = (Current Unix time - T0) / X)
        // It needs to be converted to an 8-byte array (big endian)
        byte[] data = new byte[8];
        for (int i = 8; i-- > 0; time >>>= 8) {
            data[i] = (byte) time;
        }

        Mac mac = Mac.getInstance(algorithm);
        mac.init(new SecretKeySpec(key, algorithm));
        byte[] hash = mac.doFinal(data);

        // Truncate
        int offset = hash[hash.length - 1] & 0xF;
        long binary =
                ((hash[offset] & 0x7f) << 24) |
                ((hash[offset + 1] & 0xff) << 16) |
                ((hash[offset + 2] & 0xff) << 8) |
                (hash[offset + 3] & 0xff);

        int otp = (int) (binary % Math.pow(10, returnDigits));
        return otp;
    }

    // Simple OCRA implementation (Challenge Response)
    // RFC 6287 is complex, this is a simplified version.
    public String generateOcra(String secret, String challenge) {
         try {
            Base32 base32 = new Base32();
            byte[] decodedKey = base32.decode(secret);
            byte[] challengeBytes = challenge.getBytes();

            String algorithm = "HmacSHA1";
            Mac mac = Mac.getInstance(algorithm);
            mac.init(new SecretKeySpec(decodedKey, algorithm));
            byte[] hash = mac.doFinal(challengeBytes);

            // Truncate similar to TOTP
            int offset = hash[hash.length - 1] & 0xF;
            long binary =
                    ((hash[offset] & 0x7f) << 24) |
                    ((hash[offset + 1] & 0xff) << 16) |
                    ((hash[offset + 2] & 0xff) << 8) |
                    (hash[offset + 3] & 0xff);

            int otp = (int) (binary % Math.pow(10, 6));
            return String.format("%06d", otp);
         } catch (Exception e) {
             e.printStackTrace();
             return null;
         }
    }

    public boolean validateOcra(String secret, String challenge, String otp) {
        String generated = generateOcra(secret, challenge);
        return generated != null && generated.equals(otp);
    }
}
