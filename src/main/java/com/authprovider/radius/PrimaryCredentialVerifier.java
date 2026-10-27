package com.authprovider.radius;

import com.authprovider.entity.User;
import com.authprovider.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
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

@Slf4j
@Component
public class PrimaryCredentialVerifier {

    private static final byte[] DUMMY_PASSWORD_DIGEST = sha256("\u0000radius-dummy-password\u0000".getBytes(StandardCharsets.UTF_8));

    private final UserRepository userRepository;
    private final RadiusProperties properties;

    public PrimaryCredentialVerifier(UserRepository userRepository, RadiusProperties properties) {
        this.userRepository = userRepository;
        this.properties = properties;
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
        byte[] supplied = sha256(suppliedPassword);
        String stored = user == null ? null : user.getPassword();
        byte[] expected = stored == null || stored.isEmpty()
                ? DUMMY_PASSWORD_DIGEST
                : sha256(stored.getBytes(StandardCharsets.UTF_8));
        boolean matches = MessageDigest.isEqual(expected, supplied);
        return matches && stored != null && !stored.isEmpty() && suppliedPassword.length > 0;
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
