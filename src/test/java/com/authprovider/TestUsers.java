package com.authprovider;

import com.authprovider.entity.OtpToken;

/** Test helpers for accounts: OTP secrets are only stored in {@link OtpToken}. */
public final class TestUsers {

    private TestUsers() {
    }

    /** A new (unsaved) enabled OTP token carrying {@code secret}; persisted when the user is saved via UserService
     * ({@code null} when {@code secret} is {@code null}). */
    public static OtpToken token(String secret) {
        if (secret == null) {
            return null;
        }
        return OtpToken.builder().secret(secret).enabled(true).build();
    }
}
