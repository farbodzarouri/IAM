package com.authprovider.oauth2;

import com.authprovider.entity.OAuthClient;
import com.authprovider.repository.OAuthClientRepository;
import com.authprovider.service.AccountLockoutService;
import com.authprovider.service.PasswordService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.net.URLDecoder;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Locale;
import java.util.Optional;

/**
 * Authenticates confidential OAuth 2.0 clients with HTTP Basic ({@code client_secret_basic}, RFC 6749
 * section 2.3.1, RFC 7617). Brute-force protection follows the persistent {@code SecurityPolicy}
 * ({@code maxFailures}, {@code failureWindowSeconds}, {@code lockoutSeconds}) through the cluster-wide
 * {@link AccountLockoutService} ({@code OAUTH_CLIENT} scope): each secret verification is reserved before
 * the (BCrypt) comparison, so concurrent guesses on several nodes cannot exceed the threshold. Unknown,
 * disabled, blocked and locked clients incur the same BCrypt work to equalize response timing.
 */
@Slf4j
@Component
public class ClientAuthenticator {

    /** BCrypt only evaluates the first 72 bytes; longer secrets are never accepted. */
    public static final int MAX_SECRET_BYTES = 72;
    private static final int MAX_HEADER_LENGTH = 1024;

    public enum Status {
        AUTHENTICATED,
        /** No client authentication was supplied. */
        MISSING,
        /** Unsupported scheme or malformed Basic credentials. */
        MALFORMED,
        UNKNOWN_CLIENT,
        INVALID_SECRET,
        CLIENT_DISABLED,
        CLIENT_BLOCKED,
        LOCKED_OUT
    }

    public record Result(Status status, String clientId, OAuthClient client, boolean newlyLocked) {
        public boolean isAuthenticated() {
            return status == Status.AUTHENTICATED && client != null;
        }
    }

    private final OAuthClientRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final PasswordService passwordService;
    private final AccountLockoutService lockoutService;

    public ClientAuthenticator(OAuthClientRepository repository, PasswordEncoder passwordEncoder,
                               PasswordService passwordService, AccountLockoutService lockoutService) {
        this.repository = repository;
        this.passwordEncoder = passwordEncoder;
        this.passwordService = passwordService;
        this.lockoutService = lockoutService;
    }

    public Result authenticate(String authorizationHeader) {
        if (authorizationHeader == null || authorizationHeader.isBlank()) {
            return new Result(Status.MISSING, null, null, false);
        }
        Optional<String[]> credentials = parseBasic(authorizationHeader);
        if (credentials.isEmpty()) {
            return new Result(Status.MALFORMED, null, null, false);
        }
        String clientId = credentials.get()[0];
        String secret = credentials.get()[1];
        if (clientId.isEmpty() || secret.isEmpty()) {
            passwordService.simulateCheck(secret);
            return new Result(Status.MALFORMED, clientId.isEmpty() ? null : clientId, null, false);
        }

        Optional<OAuthClient> found = repository.findByClientId(clientId);
        if (found.isEmpty()) {
            passwordService.simulateCheck(secret);
            return new Result(Status.UNKNOWN_CLIENT, clientId, null, false);
        }
        OAuthClient client = found.get();
        if (!client.isEnabled()) {
            passwordService.simulateCheck(secret);
            return new Result(Status.CLIENT_DISABLED, clientId, client, false);
        }
        if (client.isBlocked()) {
            passwordService.simulateCheck(secret);
            return new Result(Status.CLIENT_BLOCKED, clientId, client, false);
        }
        if (!lockoutService.tryBeginClientAttempt(client.getId())) {
            passwordService.simulateCheck(secret);
            return new Result(Status.LOCKED_OUT, clientId, client, false);
        }
        boolean matches;
        if (secret.getBytes(StandardCharsets.UTF_8).length > MAX_SECRET_BYTES) {
            passwordService.simulateCheck(secret);
            matches = false;
        } else {
            matches = passwordEncoder.matches(secret, client.getClientSecretHash());
        }
        if (!matches) {
            boolean locked = lockoutService.confirmClientFailure(client.getId());
            if (locked) {
                log.warn("OAuth 2.0 client '{}' locked out after repeated authentication failures", clientId);
            }
            return new Result(Status.INVALID_SECRET, clientId, client, locked);
        }
        lockoutService.recordClientSuccess(client.getId());
        return new Result(Status.AUTHENTICATED, clientId, client, false);
    }

    /** Extracts the form-urlencoded client id and secret from a {@code Basic} authorization header. */
    static Optional<String[]> parseBasic(String header) {
        if (header.length() > MAX_HEADER_LENGTH) {
            return Optional.empty();
        }
        String trimmed = header.strip();
        int space = trimmed.indexOf(' ');
        if (space <= 0 || !trimmed.substring(0, space).toLowerCase(Locale.ROOT).equals("basic")) {
            return Optional.empty();
        }
        String token = trimmed.substring(space + 1).strip();
        if (token.isEmpty()) {
            return Optional.empty();
        }
        String decoded;
        try {
            byte[] raw = Base64.getDecoder().decode(token);
            decoded = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(raw))
                    .toString();
        } catch (IllegalArgumentException | CharacterCodingException e) {
            return Optional.empty();
        }
        int colon = decoded.indexOf(':');
        if (colon < 0) {
            return Optional.empty();
        }
        try {
            String id = URLDecoder.decode(decoded.substring(0, colon), StandardCharsets.UTF_8);
            String secret = URLDecoder.decode(decoded.substring(colon + 1), StandardCharsets.UTF_8);
            for (int i = 0; i < id.length(); i++) {
                if (Character.isISOControl(id.charAt(i))) {
                    return Optional.empty();
                }
            }
            return Optional.of(new String[]{id, secret});
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }
}
