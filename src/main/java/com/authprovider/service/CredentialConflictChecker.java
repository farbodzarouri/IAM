package com.authprovider.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Enforces privilege separation invariants between {@link com.authprovider.entity.User} and
 * {@link com.authprovider.entity.Admin} accounts owned by the same {@link com.authprovider.entity.Person}.
 */
final class CredentialConflictChecker {

    private CredentialConflictChecker() {
    }

    static boolean sameOrOverlappingUsername(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        String ta = a.trim();
        String tb = b.trim();
        if (ta.equalsIgnoreCase(tb)) {
            return true;
        }
        String na = UsernameNormalizer.normalize(ta);
        String nb = UsernameNormalizer.normalize(tb);
        return na != null && na.equals(nb) && (na.equalsIgnoreCase(ta) || nb.equalsIgnoreCase(tb));
    }

    static boolean passwordMatches(PasswordService passwordService, String storedPassword, String candidatePassword) {
        if (storedPassword == null || storedPassword.isBlank() || candidatePassword == null || candidatePassword.isBlank()) {
            return false;
        }
        if (passwordService.isEncoded(candidatePassword)) {
            return MessageDigest.isEqual(
                    storedPassword.getBytes(StandardCharsets.UTF_8),
                    candidatePassword.getBytes(StandardCharsets.UTF_8));
        }
        return passwordService.matches(storedPassword, candidatePassword);
    }
}
