package com.authprovider.oauth2;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Base64;

/**
 * Strict unpadded base64url encoding (RFC 4648 section 5) as required by RFC 7515 section 2. Decoding
 * rejects padding, characters outside the URL-safe alphabet, and non-canonical encodings so that a JWS
 * cannot be altered without invalidating it.
 */
public final class Base64Url {

    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

    private Base64Url() {
    }

    public static String encode(byte[] data) {
        return ENCODER.encodeToString(data);
    }

    /**
     * @throws IllegalArgumentException if {@code value} is not a canonical unpadded base64url string
     */
    public static byte[] decode(String value) {
        if (value == null) {
            throw new IllegalArgumentException("base64url value is missing");
        }
        if (value.length() % 4 == 1) {
            throw new IllegalArgumentException("Invalid base64url length");
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            boolean valid = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || c == '-' || c == '_';
            if (!valid) {
                throw new IllegalArgumentException("Invalid base64url character");
            }
        }
        byte[] decoded = DECODER.decode(value);
        if (!ENCODER.encodeToString(decoded).equals(value)) {
            throw new IllegalArgumentException("Non-canonical base64url encoding");
        }
        return decoded;
    }

    /** Encodes a non-negative integer as an RFC 7518 section 2 Base64urlUInt (minimal big-endian octets). */
    public static String encodeUnsigned(BigInteger value) {
        if (value.signum() < 0) {
            throw new IllegalArgumentException("Negative value");
        }
        byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            bytes = Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return encode(bytes);
    }

    public static BigInteger decodeUnsigned(String value) {
        return new BigInteger(1, decode(value));
    }
}
