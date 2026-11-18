package com.authprovider.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * BCrypt-backed implementation of {@link PasswordService}.
 */
@Service
public class PasswordServiceImpl implements PasswordService {

    private static final String BCRYPT_PREFIX = "{bcrypt}";
    private static final String NOOP_PREFIX = "{noop}";

    private final PasswordEncoder passwordEncoder;
    private final String dummyHash;

    @Autowired
    public PasswordServiceImpl(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
        this.dummyHash = passwordEncoder.encode("\u0000iam-dummy-password\u0000");
    }

    @Override
    public String encode(String rawPassword) {
        if (rawPassword == null) {
            return null;
        }
        if (rawPassword.isBlank()) {
            return rawPassword;
        }
        if (rawPassword.startsWith(BCRYPT_PREFIX)) {
            return rawPassword.substring(BCRYPT_PREFIX.length());
        }
        if (isRawBcryptHash(rawPassword)) {
            return rawPassword;
        }
        return passwordEncoder.encode(rawPassword);
    }

    @Override
    public boolean isEncoded(String password) {
        return password != null && (isRawBcryptHash(password) || password.startsWith(BCRYPT_PREFIX));
    }

    @Override
    public boolean matches(String storedPassword, String candidatePassword) {
        if (storedPassword == null || storedPassword.isEmpty() || candidatePassword == null) {
            return false;
        }
        if (isRawBcryptHash(storedPassword)) {
            return passwordEncoder.matches(candidatePassword, storedPassword);
        }
        if (storedPassword.startsWith(BCRYPT_PREFIX)) {
            return passwordEncoder.matches(candidatePassword, storedPassword.substring(BCRYPT_PREFIX.length()));
        }
        if (storedPassword.startsWith(NOOP_PREFIX)) {
            return constantTimeEquals(candidatePassword, storedPassword.substring(NOOP_PREFIX.length()));
        }
        return constantTimeEquals(candidatePassword, storedPassword);
    }

    @Override
    public void simulateCheck(String candidatePassword) {
        passwordEncoder.matches(candidatePassword == null ? "" : candidatePassword, dummyHash);
    }

    private static boolean isRawBcryptHash(String value) {
        return value.startsWith("$2a$") || value.startsWith("$2b$") || value.startsWith("$2y$");
    }

    private static boolean constantTimeEquals(String a, String b) {
        return MessageDigest.isEqual(
                a.getBytes(StandardCharsets.UTF_8),
                b.getBytes(StandardCharsets.UTF_8));
    }
}
