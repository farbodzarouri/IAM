package com.authprovider.radius;

import com.authprovider.config.LdapProperties;
import com.authprovider.entity.User;
import com.authprovider.ldap.DirectoryAuthenticationResult;
import com.authprovider.ldap.DirectoryAuthenticator;
import com.authprovider.ldap.DirectoryConfiguration;
import com.authprovider.ldap.LdapPropertiesDirectoryConfiguration;
import com.authprovider.repository.UserRepository;
import com.authprovider.service.AccountLockoutService;
import com.authprovider.service.AccountResolver;
import com.authprovider.service.PasswordService;
import com.authprovider.service.SecurityPolicyService;
import com.authprovider.service.UsernameNormalizer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.function.Predicate;

@Slf4j
@Component
public class PrimaryCredentialVerifier {

    static final String SOURCE_LOCAL = "LOCAL";
    static final String SOURCE_DIRECTORY = "LDAP";

    private final UserRepository userRepository;
    private final DirectoryConfiguration directoryConfiguration;
    private final DirectoryAuthenticator directoryAuthenticator;
    private final AccountLockoutService lockoutService;
    private final SecurityPolicyService policyService;
    private final PasswordService passwordService;
    private final AccountResolver<User> accountResolver;

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

    public PrimaryCredentialVerifier(UserRepository userRepository) {
        this(userRepository, (DirectoryConfiguration) null, null, null, null, null);
    }

    public PrimaryCredentialVerifier(UserRepository userRepository,
                                     LdapProperties ldapProperties,
                                     DirectoryAuthenticator directoryAuthenticator) {
        this(userRepository,
                ldapProperties == null ? null : new LdapPropertiesDirectoryConfiguration(ldapProperties),
                directoryAuthenticator,
                null,
                null,
                null);
    }

    @Autowired
    public PrimaryCredentialVerifier(UserRepository userRepository,
                                     DirectoryConfiguration directoryConfiguration,
                                     DirectoryAuthenticator directoryAuthenticator,
                                     AccountLockoutService lockoutService,
                                     SecurityPolicyService policyService,
                                     PasswordService passwordService) {
        this.userRepository = userRepository;
        this.directoryConfiguration = directoryConfiguration;
        this.directoryAuthenticator = directoryAuthenticator;
        this.lockoutService = lockoutService;
        this.policyService = policyService != null ? policyService : SecurityPolicyService.withDefaults();
        this.passwordService = passwordService != null ? passwordService : PasswordService.withDefaults();
        this.accountResolver = new AccountResolver<>(
                userRepository == null ? null : userRepository::findAllByUsernameIgnoreCase,
                this::findExact);
    }

    public boolean isDirectoryEnabled() {
        return directoryConfiguration != null && directoryAuthenticator != null && directoryConfiguration.isEnabled();
    }

    /**
     * Verifies primary credentials expecting a second-factor OTP secret to be enrolled on the
     * resolved account.
     */
    public Verification verify(String userName, byte[] password, Predicate<Long> isLocked) {
        return verify(userName, password, isLocked, true);
    }

    /**
     * Verifies the primary credentials of a RADIUS user. When {@code requireEnrollment} is {@code false}
     * (password-only authentication), existing accounts without an enrolled OTP secret are permitted.
     * RADIUS never auto-provisions local accounts from a directory.
     */
    public Verification verify(String userName, byte[] password, Predicate<Long> isLocked, boolean requireEnrollment) {
        Optional<User> localUser = findUser(userName);
        if (localUser.isPresent() && isBlocked(localUser.get(), isLocked)) {
            simulatePasswordCheck(password);
            return new Verification(Outcome.LOCKED, localUser.get(), sourceLabel());
        }
        if (isDirectoryEnabled()) {
            return verifyWithDirectory(userName, password, localUser, isLocked, requireEnrollment);
        }
        return verifyLocal(localUser, password, SOURCE_LOCAL, requireEnrollment);
    }

    private boolean isBlocked(User user, Predicate<Long> isLocked) {
        if (!user.isAccountEnabled() || isLocked.test(user.getId())) {
            return true;
        }
        return lockoutService != null && user.getOtpToken() != null
                && lockoutService.isTokenLocked(user.getOtpToken().getId());
    }

    private Verification verifyLocal(Optional<User> localUser, byte[] password, String source,
                                     boolean requireEnrollment) {
        if (localUser.isEmpty()) {
            simulatePasswordCheck(password);
            return new Verification(Outcome.UNKNOWN_USER, null, source);
        }
        User user = localUser.get();
        if (!passwordMatches(user, password)) {
            return new Verification(Outcome.INVALID_CREDENTIALS, user, source);
        }
        if (requireEnrollment && !isEnrolled(user)) {
            return new Verification(Outcome.NOT_ENROLLED, user, source);
        }
        return new Verification(Outcome.AUTHENTICATED, user, source);
    }

    private Verification verifyWithDirectory(String userName, byte[] password, Optional<User> localUser,
                                             Predicate<Long> isLocked, boolean requireEnrollment) {
        if (password == null || password.length == 0) {
            return new Verification(Outcome.INVALID_CREDENTIALS, localUser.orElse(null), SOURCE_DIRECTORY);
        }
        String loginName = directoryLoginName(userName);
        DirectoryAuthenticationResult result;
        try {
            String rawPassword = new String(password, StandardCharsets.UTF_8);
            result = directoryAuthenticator.isRealmAware()
                    ? directoryAuthenticator.authenticateQualified(userName.trim(), loginName, rawPassword)
                    : directoryAuthenticator.authenticate(loginName, rawPassword);
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
                Optional<User> linked = findLinkedAccount(canonical);
                if (linked.isEmpty()) {
                    log.warn("Directory user '{}' has no local account; enroll before using RADIUS",
                            RadiusAuthenticationHandler.sanitize(canonical));
                    return new Verification(Outcome.NOT_ENROLLED, null, SOURCE_DIRECTORY);
                }
                User user = linked.get();
                if (isBlocked(user, isLocked)) {
                    return new Verification(Outcome.LOCKED, user, SOURCE_DIRECTORY);
                }
                if (requireEnrollment && !isEnrolled(user)) {
                    return new Verification(Outcome.NOT_ENROLLED, user, SOURCE_DIRECTORY);
                }
                return new Verification(Outcome.AUTHENTICATED, user, SOURCE_DIRECTORY);
            }
            case USER_NOT_FOUND:
                if (directoryConfiguration.isFallbackToLocal(userName)) {
                    return verifyLocal(localUser, password, SOURCE_LOCAL, requireEnrollment);
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
        if (isStripRealm()) {
            String stripped = UsernameNormalizer.stripRealm(name);
            name = stripped == null ? "" : stripped;
        }
        return name.isEmpty() ? userName.trim() : name;
    }

    private boolean isStripRealm() {
        return policyService.current().isStripRealm();
    }

    private String sourceLabel() {
        return isDirectoryEnabled() ? SOURCE_DIRECTORY : SOURCE_LOCAL;
    }

    static boolean isEnrolled(User user) {
        return user != null && user.getSecret() != null && !user.getSecret().isBlank();
    }

    /**
     * Resolves a RADIUS user name to the canonical local account using the shared {@link AccountResolver}
     * rules (identical for web login, MFA pre-authentication and RADIUS). Ambiguous names resolve to nothing.
     */
    public Optional<User> findUser(String userName) {
        if (userName == null || userName.isEmpty()) {
            return Optional.empty();
        }
        return accountResolver.resolve(userName, isStripRealm()).asOptional();
    }

    /**
     * Links an authenticated directory identity to its local account. The canonical name reported by the
     * directory is authoritative and is matched as is (no realm stripping), using the same rule as web login.
     */
    public Optional<User> findLinkedAccount(String canonicalName) {
        if (canonicalName == null || canonicalName.isBlank()) {
            return Optional.empty();
        }
        return accountResolver.resolve(canonicalName, false).asOptional();
    }

    private Optional<User> findExact(String candidate) {
        if (userRepository == null) {
            return Optional.empty();
        }
        try {
            return userRepository.findByUsername(candidate);
        } catch (IncorrectResultSizeDataAccessException e) {
            log.error("Multiple users share the username '{}'; refusing RADIUS authentication",
                    RadiusAuthenticationHandler.sanitize(candidate));
            return Optional.empty();
        }
    }

    public boolean passwordMatches(User user, byte[] suppliedPassword) {
        if (user == null || user.getPassword() == null || user.getPassword().isEmpty()
                || suppliedPassword == null || suppliedPassword.length == 0) {
            simulatePasswordCheck(suppliedPassword);
            return false;
        }
        return passwordService.matches(user.getPassword(), new String(suppliedPassword, StandardCharsets.UTF_8));
    }

    public void simulatePasswordCheck(byte[] suppliedPassword) {
        String candidate = suppliedPassword == null ? "" : new String(suppliedPassword, StandardCharsets.UTF_8);
        passwordService.simulateCheck(candidate);
    }
}
