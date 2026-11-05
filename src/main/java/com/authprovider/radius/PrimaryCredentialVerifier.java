package com.authprovider.radius;

import com.authprovider.config.LdapProperties;
import com.authprovider.entity.User;
import com.authprovider.ldap.DirectoryAuthenticationResult;
import com.authprovider.ldap.DirectoryAuthenticator;
import com.authprovider.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;

@Slf4j
@Component
public class PrimaryCredentialVerifier {

    static final String SOURCE_LOCAL = "LOCAL";
    static final String SOURCE_DIRECTORY = "LDAP";
    private static final byte[] DUMMY_PASSWORD_DIGEST = sha256("\u0000radius-dummy-password\u0000".getBytes(StandardCharsets.UTF_8));

    private final UserRepository userRepository;
    private final RadiusProperties properties;
    private final LdapProperties ldapProperties;
    private final DirectoryAuthenticator directoryAuthenticator;
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    public enum Outcome {
        AUTHENTICATED,
        UNKNOWN_USER,
        LOCKED,
        INVALID_CREDENTIALS,
        NOT_ENROLLED,
        DIRECTORY_UNAVAILABLE
    }

    /**
     * Result of primary (first factor) verification. {@code user} is the local account the
     * outcome applies to, when one is known (used for lockout accounting and the OTP challenge).
     */
    public record Verification(Outcome outcome, User user, String source) {
        public boolean isAuthenticated() {
            return outcome == Outcome.AUTHENTICATED;
        }
    }

    public PrimaryCredentialVerifier(UserRepository userRepository, RadiusProperties properties) {
        this(userRepository, properties, null, null);
    }

    @Autowired
    public PrimaryCredentialVerifier(UserRepository userRepository, RadiusProperties properties,
                                     LdapProperties ldapProperties, DirectoryAuthenticator directoryAuthenticator) {
        this.userRepository = userRepository;
        this.properties = properties;
        this.ldapProperties = ldapProperties;
        this.directoryAuthenticator = directoryAuthenticator;
    }

    public boolean isDirectoryEnabled() {
        return ldapProperties != null && ldapProperties.isEnabled() && directoryAuthenticator != null;
    }

    /**
     * Verifies the primary credentials of a RADIUS user. When LDAP is enabled the password is verified
     * against the directory and the directory identity is linked to an already enrolled local account
     * (no just-in-time provisioning over RADIUS); local passwords are only consulted for accounts unknown
     * to the directory and only if {@code ldap.fallback-to-local=true}. Otherwise the local user store is used.
     */
    public Verification verify(String userName, byte[] password, Predicate<Long> isLocked) {
        Optional<User> localUser = findUser(userName);
        if (localUser.isPresent() && isLocked.test(localUser.get().getId())) {
            simulatePasswordCheck(password);
            return new Verification(Outcome.LOCKED, localUser.get(), sourceLabel());
        }
        if (isDirectoryEnabled()) {
            return verifyWithDirectory(userName, password, localUser, isLocked);
        }
        return verifyLocal(localUser, password, SOURCE_LOCAL);
    }

    private Verification verifyLocal(Optional<User> localUser, byte[] password, String source) {
        if (localUser.isEmpty()) {
            simulatePasswordCheck(password);
            return new Verification(Outcome.UNKNOWN_USER, null, source);
        }
        User user = localUser.get();
        if (!passwordMatches(user, password)) {
            return new Verification(Outcome.INVALID_CREDENTIALS, user, source);
        }
        if (!isEnrolled(user)) {
            return new Verification(Outcome.NOT_ENROLLED, user, source);
        }
        return new Verification(Outcome.AUTHENTICATED, user, source);
    }

    private Verification verifyWithDirectory(String userName, byte[] password, Optional<User> localUser,
                                             Predicate<Long> isLocked) {
        if (password == null || password.length == 0) {
            return new Verification(Outcome.INVALID_CREDENTIALS, localUser.orElse(null), SOURCE_DIRECTORY);
        }
        String loginName = directoryLoginName(userName);
        DirectoryAuthenticationResult result;
        try {
            result = directoryAuthenticator.authenticate(loginName, new String(password, StandardCharsets.UTF_8));
        } catch (RuntimeException e) {
            log.error("Directory authentication for RADIUS user '{}' failed unexpectedly",
                    RadiusAuthenticationHandler.sanitize(loginName), e);
            result = DirectoryAuthenticationResult.unavailable();
        }
        if (result == null) {
            result = DirectoryAuthenticationResult.unavailable();
        }
        switch (result.status()) {
            case AUTHENTICATED: {
                String canonical = result.username() != null && !result.username().isBlank()
                        ? result.username() : loginName;
                Optional<User> linked = findUser(canonical);
                if (linked.isEmpty()) {
                    log.warn("Directory user '{}' has no enrolled local account; complete two-factor enrollment "
                            + "before using RADIUS", RadiusAuthenticationHandler.sanitize(canonical));
                    return new Verification(Outcome.NOT_ENROLLED, null, SOURCE_DIRECTORY);
                }
                User user = linked.get();
                if (isLocked.test(user.getId())) {
                    return new Verification(Outcome.LOCKED, user, SOURCE_DIRECTORY);
                }
                if (!isEnrolled(user)) {
                    return new Verification(Outcome.NOT_ENROLLED, user, SOURCE_DIRECTORY);
                }
                return new Verification(Outcome.AUTHENTICATED, user, SOURCE_DIRECTORY);
            }
            case USER_NOT_FOUND:
                if (ldapProperties.isFallbackToLocal()) {
                    return verifyLocal(localUser, password, SOURCE_LOCAL);
                }
                return new Verification(Outcome.UNKNOWN_USER, null, SOURCE_DIRECTORY);
            case UNAVAILABLE:
                return new Verification(Outcome.DIRECTORY_UNAVAILABLE, null, SOURCE_DIRECTORY);
            case INVALID_CREDENTIALS:
            default:
                return new Verification(Outcome.INVALID_CREDENTIALS, localUser.orElse(null), SOURCE_DIRECTORY);
        }
    }

    String directoryLoginName(String userName) {
        String name = userName.trim();
        if (properties.isStripRealm()) {
            int backslash = name.lastIndexOf('\\');
            if (backslash >= 0) {
                name = name.substring(backslash + 1);
            }
            int at = name.indexOf('@');
            if (at >= 0) {
                name = name.substring(0, at);
            }
            name = name.trim();
        }
        return name.isEmpty() ? userName.trim() : name;
    }

    private String sourceLabel() {
        return isDirectoryEnabled() ? SOURCE_DIRECTORY : SOURCE_LOCAL;
    }

    private static boolean isEnrolled(User user) {
        return user.getSecret() != null && !user.getSecret().isBlank();
    }

    public Optional<User> findUser(String userName) {
        List<String> candidates = candidateUserNames(userName);
        for (String candidate : candidates) {
            Optional<User> user;
            try {
                user = userRepository.findByUsername(candidate);
            } catch (IncorrectResultSizeDataAccessException e) {
                log.error("Multiple users share the username '{}'; refusing RADIUS authentication",
                        RadiusAuthenticationHandler.sanitize(candidate));
                return Optional.empty();
            }
            if (user != null && user.isPresent()) {
                return user;
            }
        }
        for (String candidate : candidates) {
            List<User> matches = userRepository.findAllByUsernameIgnoreCase(candidate);
            if (matches != null && !matches.isEmpty()) {
                if (matches.size() > 1) {
                    log.error("Multiple users match username '{}' case-insensitively; refusing RADIUS authentication",
                            RadiusAuthenticationHandler.sanitize(candidate));
                    return Optional.empty();
                }
                return Optional.of(matches.get(0));
            }
        }
        return Optional.empty();
    }

    public boolean passwordMatches(User user, byte[] suppliedPassword) {
        if (user == null || user.getPassword() == null || user.getPassword().isEmpty()
                || suppliedPassword == null || suppliedPassword.length == 0) {
            simulatePasswordCheck(suppliedPassword);
            return false;
        }
        String stored = user.getPassword();
        String raw = new String(suppliedPassword, StandardCharsets.UTF_8);
        if (stored.startsWith("$2a$") || stored.startsWith("$2b$") || stored.startsWith("$2y$")) {
            return passwordEncoder.matches(raw, stored);
        }
        byte[] supplied = sha256(suppliedPassword);
        byte[] expected = sha256(stored.getBytes(StandardCharsets.UTF_8));
        boolean matches = MessageDigest.isEqual(expected, supplied);
        return matches;
    }

    public void simulatePasswordCheck(byte[] suppliedPassword) {
        MessageDigest.isEqual(DUMMY_PASSWORD_DIGEST, sha256(suppliedPassword));
    }

    List<String> candidateUserNames(String userName) {
        if (userName == null || userName.isEmpty()) {
            return List.of();
        }
        Set<String> candidates = new LinkedHashSet<>();
        candidates.add(userName);
        if (properties.isStripRealm()) {
            String stripped = userName.trim();
            int backslash = stripped.lastIndexOf('\\');
            if (backslash >= 0) {
                stripped = stripped.substring(backslash + 1);
            }
            int at = stripped.indexOf('@');
            if (at >= 0) {
                stripped = stripped.substring(0, at);
            }
            stripped = stripped.trim();
            if (!stripped.isEmpty()) {
                candidates.add(stripped);
                candidates.add(stripped.toLowerCase(Locale.ROOT));
            }
        }
        candidates.add(userName.toLowerCase(Locale.ROOT));
        return new ArrayList<>(candidates);
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
