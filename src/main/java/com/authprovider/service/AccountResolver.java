package com.authprovider.service;

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
 * Resolves a presented user name (local login name, directory canonical name, {@code DOMAIN\\user} or
 * {@code user@realm}) to the canonical local account. The same rules apply to every channel so that a
 * person always maps to the same local account (and therefore the same lockout, replay and session state):
 * <ol>
 *     <li>candidates are tried in order: the trimmed name, then - if realm stripping is enabled - the name
 *     without {@code DOMAIN\\} prefix / {@code @realm} suffix (plus lower-case variants);</li>
 *     <li>for each candidate, a unique case-insensitive match wins; several case-insensitive matches make
 *     the name ambiguous and resolution is refused (never guessing between accounts).</li>
 * </ol>
 */
@Slf4j
public final class AccountResolver {

    public enum Status {
        FOUND,
        NOT_FOUND,
        AMBIGUOUS
    }

    public record Resolution(Status status, User user) {
        static final Resolution NOT_FOUND = new Resolution(Status.NOT_FOUND, null);
        static final Resolution AMBIGUOUS = new Resolution(Status.AMBIGUOUS, null);

        public boolean isFound() {
            return status == Status.FOUND;
        }

        public Optional<User> asOptional() {
            return Optional.ofNullable(user);
        }
    }

    private final Function<String, List<User>> caseInsensitiveLookup;
    private final Function<String, Optional<User>> exactLookup;

    /**
     * @param caseInsensitiveLookup returns all accounts whose name equals the argument ignoring case
     * @param exactLookup           optional exact (case-sensitive) lookup, may be {@code null}
     */
    public AccountResolver(Function<String, List<User>> caseInsensitiveLookup,
                           Function<String, Optional<User>> exactLookup) {
        this.caseInsensitiveLookup = caseInsensitiveLookup;
        this.exactLookup = exactLookup;
    }

    public static AccountResolver of(UserService userService) {
        return new AccountResolver(userService::findAllByUsernameIgnoreCase, null);
    }

    public Resolution resolve(String userName, boolean stripRealm) {
        for (String candidate : candidates(userName, stripRealm)) {
            List<User> matches = safe(caseInsensitiveLookup == null ? null : caseInsensitiveLookup.apply(candidate));
            if (matches.size() > 1) {
                log.error("Multiple local accounts match user name '{}' case-insensitively; refusing to resolve",
                        sanitize(candidate));
                return Resolution.AMBIGUOUS;
            }
            if (matches.size() == 1) {
                return new Resolution(Status.FOUND, matches.get(0));
            }
            if (exactLookup != null) {
                Optional<User> exact = exactLookup.apply(candidate);
                if (exact != null && exact.isPresent()) {
                    return new Resolution(Status.FOUND, exact.get());
                }
            }
        }
        return Resolution.NOT_FOUND;
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

    private static List<User> safe(List<User> users) {
        return users == null ? List.of() : users;
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
