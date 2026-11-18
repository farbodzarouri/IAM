package com.authprovider.service;

import com.authprovider.entity.Admin;
import com.authprovider.entity.User;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;

/**
 * Resolves a presented principal name (local login name, directory canonical name, {@code DOMAIN\\user} or
 * {@code user@realm}) to the canonical local account. The same rules apply to every channel so that a
 * person always maps to the same account (and therefore the same lockout, replay and session state):
 * <ol>
 *     <li>candidates are tried in order: the trimmed name, then - if realm stripping is enabled - the name
 *     without {@code DOMAIN\\} prefix / {@code @realm} suffix (plus lower-case variants);</li>
 *     <li>for each candidate, a unique case-insensitive match wins; several case-insensitive matches make
 *     the name ambiguous and resolution is refused (never guessing between accounts).</li>
 * </ol>
 */
@Slf4j
public final class AccountResolver<T> {

    public enum Status {
        FOUND,
        NOT_FOUND,
        AMBIGUOUS
    }

    public record Resolution<T>(Status status, T account) {
        private static final Resolution<?> NOT_FOUND = new Resolution<>(Status.NOT_FOUND, null);
        private static final Resolution<?> AMBIGUOUS = new Resolution<>(Status.AMBIGUOUS, null);

        @SuppressWarnings("unchecked")
        public static <T> Resolution<T> notFound() {
            return (Resolution<T>) NOT_FOUND;
        }

        @SuppressWarnings("unchecked")
        public static <T> Resolution<T> ambiguous() {
            return (Resolution<T>) AMBIGUOUS;
        }

        public boolean isFound() {
            return status == Status.FOUND;
        }

        public Optional<T> asOptional() {
            return Optional.ofNullable(account);
        }

        public T user() {
            return account;
        }
    }

    private final Function<String, List<T>> caseInsensitiveLookup;
    private final Function<String, Optional<T>> exactLookup;

    /**
     * @param caseInsensitiveLookup returns all accounts whose name equals the argument ignoring case
     * @param exactLookup           optional exact (case-sensitive) lookup, may be {@code null}
     */
    public AccountResolver(Function<String, List<T>> caseInsensitiveLookup,
                           Function<String, Optional<T>> exactLookup) {
        this.caseInsensitiveLookup = caseInsensitiveLookup;
        this.exactLookup = exactLookup;
    }

    public static AccountResolver<User> of(UserService userService) {
        return new AccountResolver<>(userService::findAllByUsernameIgnoreCase, null);
    }

    public static AccountResolver<Admin> ofAdmins(AdminService adminService) {
        return new AccountResolver<>(adminService::findAllByUsernameIgnoreCase, null);
    }

    public Resolution<T> resolve(String userName, boolean stripRealm) {
        for (String candidate : candidates(userName, stripRealm)) {
            List<T> matches = safe(caseInsensitiveLookup == null ? null : caseInsensitiveLookup.apply(candidate));
            if (matches.size() > 1) {
                log.error("Multiple local accounts match user name '{}' case-insensitively; refusing to resolve",
                        sanitize(candidate));
                return Resolution.ambiguous();
            }
            if (matches.size() == 1) {
                return new Resolution<>(Status.FOUND, matches.get(0));
            }
            if (exactLookup != null) {
                Optional<T> exact = exactLookup.apply(candidate);
                if (exact != null && exact.isPresent()) {
                    return new Resolution<>(Status.FOUND, exact.get());
                }
            }
        }
        return Resolution.notFound();
    }

    /** Candidate account names for a presented user name, most specific first. */
    public static List<String> candidates(String userName, boolean stripRealm) {
        if (userName == null || userName.isBlank()) {
            return List.of();
        }
        Set<String> candidates = new LinkedHashSet<>();
        String trimmed = userName.trim();
        candidates.add(trimmed);
        if (stripRealm) {
            String stripped = stripRealm(trimmed);
            if (!stripped.isEmpty()) {
                candidates.add(stripped);
                candidates.add(stripped.toLowerCase(Locale.ROOT));
            }
        }
        candidates.add(trimmed.toLowerCase(Locale.ROOT));
        return new ArrayList<>(candidates);
    }

    /** Removes a {@code DOMAIN\\} prefix and an {@code @realm} suffix. */
    public static String stripRealm(String userName) {
        return userName == null ? "" : UsernameNormalizer.stripRealm(userName);
    }

    private static <T> List<T> safe(List<T> accounts) {
        return accounts == null ? List.of() : accounts;
    }

    private static String sanitize(String value) {
        StringBuilder sb = new StringBuilder(Math.min(value.length(), 128));
        for (int i = 0; i < value.length() && i < 128; i++) {
            char c = value.charAt(i);
            sb.append(Character.isISOControl(c) ? '?' : c);
        }
        return sb.toString();
    }
}
