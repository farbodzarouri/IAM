package com.authprovider.service;

import java.util.Locale;

/**
 * Canonicalises account names so that the forms used by Active Directory / Windows NPS
 * ({@code DOMAIN\\user}, {@code user@realm.example}, mixed case) map to the same key.
 */
public final class UsernameNormalizer {

    private UsernameNormalizer() {
    }

    public static String normalize(String username) {
        String stripped = stripRealm(username);
        if (stripped == null || stripped.isEmpty()) {
            return null;
        }
        String name = stripped.toLowerCase(Locale.ROOT);
        return name.isEmpty() ? null : name;
    }

    /** Removes a {@code DOMAIN\\} prefix and an {@code @realm} suffix while preserving case. */
    public static String stripRealm(String username) {
        if (username == null) {
            return null;
        }
        String name = username.trim();
        int backslash = name.lastIndexOf('\\');
        if (backslash >= 0) {
            name = name.substring(backslash + 1);
        }
        int at = name.indexOf('@');
        if (at >= 0) {
            name = name.substring(0, at);
        }
        return name.trim();
    }
}
