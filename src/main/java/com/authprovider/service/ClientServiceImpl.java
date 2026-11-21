package com.authprovider.service;

import com.authprovider.dto.ClientRequest;
import com.authprovider.dto.ClientResponse;
import com.authprovider.entity.AuthAuditLog;
import com.authprovider.entity.ClientScope;
import com.authprovider.entity.OAuthClient;
import com.authprovider.exception.BadRequestException;
import com.authprovider.exception.ConflictException;
import com.authprovider.exception.ResourceNotFoundException;
import com.authprovider.oauth2.Base64Url;
import com.authprovider.oauth2.ClientAuthenticator;
import com.authprovider.repository.OAuthClientRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.function.Supplier;
import java.util.regex.Pattern;

/**
 * Default {@link ClientService}. Client secrets are BCrypt hashed and only ever returned in plain text when
 * created or rotated. Security-relevant changes (client id, secret, scopes, disabling, blocking) regenerate
 * the client's token version, invalidating all previously issued access tokens on every cluster node.
 * Administrative changes are written to the audit log.
 */
@Slf4j
@Service
public class ClientServiceImpl implements ClientService {

    /** RFC 3986 unreserved characters: safe in HTTP Basic credentials without form-encoding. */
    private static final Pattern CLIENT_ID_PATTERN = Pattern.compile("^[A-Za-z0-9._~-]{3,128}$");
    private static final int MIN_SECRET_LENGTH = 8;
    private static final int MAX_NAME_LENGTH = 128;
    private static final int GENERATED_SECRET_BYTES = 32;

    private final OAuthClientRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final AccountLockoutService lockoutService;
    private final AuthAuditService auditService;
    private final SecureRandom random;
    private final Clock clock;
    private final TransactionTemplate transactionTemplate;

    private record Change(OAuthClient client, String plainSecret, List<String> events, boolean clearLockout) {
    }

    public ClientServiceImpl(OAuthClientRepository repository, PasswordEncoder passwordEncoder,
                             AccountLockoutService lockoutService, AuthAuditService auditService,
                             SecureRandom random, Clock clock, PlatformTransactionManager transactionManager) {
        this.repository = repository;
        this.passwordEncoder = passwordEncoder;
        this.lockoutService = lockoutService;
        this.auditService = auditService;
        this.random = random;
        this.clock = clock;
        this.transactionTemplate = new TransactionTemplate(transactionManager);
    }

    @Override
    public List<ClientResponse> getAllClients() {
        return repository.findAll().stream().map(c -> toResponse(c, null)).toList();
    }

    @Override
    public ClientResponse getClient(Long id) {
        return toResponse(getOrThrow(id), null);
    }

    @Override
    public ClientResponse createClient(ClientRequest request) {
        if (request == null) {
            throw new BadRequestException("Client payload is required");
        }
        Change change = execute(() -> {
            String clientId = request.getClientId() == null || request.getClientId().isBlank()
                    ? generateClientId() : validateClientId(request.getClientId());
            if (repository.findByClientId(clientId).isPresent()) {
                throw new ConflictException("Client already exists: " + clientId);
            }
            String secret = request.getClientSecret() == null || request.getClientSecret().isEmpty()
                    ? generateSecret() : validateSecret(request.getClientSecret());
            if (request.getScopes() == null) {
                throw new BadRequestException("scopes are required (" + allowedScopes() + ")");
            }
            Instant now = clock.instant();
            OAuthClient client = OAuthClient.builder()
                    .clientId(clientId)
                    .clientSecretHash(passwordEncoder.encode(secret))
                    .name(request.getName() == null || request.getName().isBlank()
                            ? clientId : validateName(request.getName()))
                    .enabled(request.getEnabled() == null || request.getEnabled())
                    .blocked(request.getBlocked() != null && request.getBlocked())
                    .authMode(request.getAuthMode())
                    .scopes(parseScopes(request.getScopes()))
                    .tokenVersion(newTokenVersion())
                    .secretRotatedAt(now)
                    .build();
            return new Change(repository.saveAndFlush(client), secret, List.of("CLIENT_CREATED"), false);
        });
        audit(change);
        return toResponse(change.client(), change.plainSecret());
    }

    @Override
    public ClientResponse updateClient(Long id, ClientRequest request) {
        if (request == null) {
            throw new BadRequestException("Client payload is required");
        }
        Change change = execute(() -> {
            OAuthClient client = getOrThrow(id);
            List<String> events = new ArrayList<>();
            events.add("CLIENT_UPDATED");
            boolean invalidateTokens = false;
            String plainSecret = null;

            if (request.getClientId() != null && !request.getClientId().equals(client.getClientId())) {
                String clientId = validateClientId(request.getClientId());
                repository.findByClientId(clientId).ifPresent(other -> {
                    if (!Objects.equals(other.getId(), id)) {
                        throw new ConflictException("Client already exists: " + clientId);
                    }
                });
                client.setClientId(clientId);
                invalidateTokens = true;
            }
            if (request.getClientSecret() != null && !request.getClientSecret().isEmpty()) {
                plainSecret = validateSecret(request.getClientSecret());
                client.setClientSecretHash(passwordEncoder.encode(plainSecret));
                client.setSecretRotatedAt(clock.instant());
                events.add("SECRET_ROTATED");
                invalidateTokens = true;
            }
            if (request.getName() != null) {
                client.setName(validateName(request.getName()));
            }
            if (request.getEnabled() != null) {
                if (client.isEnabled() && !request.getEnabled()) {
                    events.add("CLIENT_DISABLED");
                    invalidateTokens = true;
                } else if (!client.isEnabled() && request.getEnabled()) {
                    events.add("CLIENT_ENABLED");
                }
                client.setEnabled(request.getEnabled());
            }
            boolean clearLockout = false;
            if (request.getBlocked() != null) {
                if (request.getBlocked()) {
                    if (!client.isBlocked()) {
                        events.add("CLIENT_BLOCKED");
                        invalidateTokens = true;
                    }
                } else {
                    clearLockout = true;
                    if (client.isBlocked() || lockoutService.isClientLocked(client.getId())) {
                        events.add("CLIENT_UNBLOCKED");
                    }
                }
                client.setBlocked(request.getBlocked());
            }
            if (request.isAuthModeSpecified()) {
                client.setAuthMode(request.getAuthMode());
            }
            if (request.getScopes() != null) {
                Set<ClientScope> scopes = parseScopes(request.getScopes());
                if (!scopes.equals(client.getScopes())) {
                    client.setScopes(scopes);
                    events.add("SCOPES_CHANGED");
                    invalidateTokens = true;
                }
            }
            if (invalidateTokens) {
                client.setTokenVersion(newTokenVersion());
                events.add("TOKENS_INVALIDATED");
            }
            return new Change(repository.saveAndFlush(client), plainSecret, events, clearLockout);
        });
        if (change.clearLockout()) {
            lockoutService.clearClientLockout(change.client().getId());
        }
        audit(change);
        return toResponse(change.client(), change.plainSecret());
    }

    @Override
    public ClientResponse rotateSecret(Long id) {
        Change change = execute(() -> {
            OAuthClient client = getOrThrow(id);
            String secret = generateSecret();
            client.setClientSecretHash(passwordEncoder.encode(secret));
            client.setSecretRotatedAt(clock.instant());
            client.setTokenVersion(newTokenVersion());
            return new Change(repository.saveAndFlush(client), secret,
                    List.of("SECRET_ROTATED", "TOKENS_INVALIDATED"), false);
        });
        audit(change);
        return toResponse(change.client(), change.plainSecret());
    }

    @Override
    public void deleteClient(Long id) {
        Change change = execute(() -> {
            OAuthClient client = getOrThrow(id);
            repository.delete(client);
            repository.flush();
            return new Change(client, null, List.of("CLIENT_DELETED"), true);
        });
        lockoutService.clearClientLockout(change.client().getId());
        audit(change);
    }

    private OAuthClient getOrThrow(Long id) {
        if (id == null) {
            throw new ResourceNotFoundException("Client not found: null");
        }
        return repository.findById(id).orElseThrow(() -> new ResourceNotFoundException("Client not found: " + id));
    }

    private Change execute(Supplier<Change> work) {
        try {
            return transactionTemplate.execute(status -> work.get());
        } catch (DataIntegrityViolationException e) {
            throw new ConflictException("Client already exists or violates a constraint");
        } catch (OptimisticLockingFailureException e) {
            throw new ConflictException("Client was modified concurrently; retry the request");
        }
    }

    private ClientResponse toResponse(OAuthClient client, String plainSecret) {
        Instant lockedUntil = lockoutService.clientLockedUntil(client.getId()).orElse(null);
        boolean locked = lockedUntil != null || lockoutService.isClientLocked(client.getId());
        return ClientResponse.builder()
                .id(client.getId())
                .clientId(client.getClientId())
                .clientSecret(plainSecret)
                .name(client.getName())
                .enabled(client.isEnabled())
                .blocked(client.isBlocked())
                .locked(locked)
                .lockedUntil(lockedUntil)
                .authMode(client.getAuthMode())
                .scopes(client.getScopes().stream().sorted().map(ClientScope::value).toList())
                .secretRotatedAt(client.getSecretRotatedAt())
                .createdAt(client.getCreatedAt())
                .updatedAt(client.getUpdatedAt())
                .build();
    }

    private void audit(Change change) {
        String admin = currentAdmin();
        for (String event : change.events()) {
            auditService.event(AuthAuditLog.Channel.OAUTH2_CLIENT_ADMIN, AuthAuditLog.Outcome.SUCCESS)
                    .username(admin)
                    .clientName(change.client().getClientId())
                    .reason(event)
                    .log();
        }
        log.info("OAuth 2.0 client '{}' changed by '{}': {}", change.client().getClientId(), admin, change.events());
    }

    private static String currentAdmin() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication == null ? null : authentication.getName();
    }

    private static String validateClientId(String value) {
        String clientId = value.trim();
        if (!CLIENT_ID_PATTERN.matcher(clientId).matches()) {
            throw new BadRequestException("clientId must be 3-128 characters of A-Z a-z 0-9 . _ ~ -");
        }
        return clientId;
    }

    private static String validateSecret(String secret) {
        if (secret.length() < MIN_SECRET_LENGTH) {
            throw new BadRequestException("clientSecret must be at least " + MIN_SECRET_LENGTH + " characters");
        }
        if (secret.getBytes(StandardCharsets.UTF_8).length > ClientAuthenticator.MAX_SECRET_BYTES) {
            throw new BadRequestException("clientSecret must not exceed " + ClientAuthenticator.MAX_SECRET_BYTES
                    + " bytes");
        }
        for (int i = 0; i < secret.length(); i++) {
            if (Character.isISOControl(secret.charAt(i))) {
                throw new BadRequestException("clientSecret must not contain control characters");
            }
        }
        return secret;
    }

    private static String validateName(String value) {
        String name = value.trim();
        if (name.isEmpty() || name.length() > MAX_NAME_LENGTH) {
            throw new BadRequestException("name must be 1-" + MAX_NAME_LENGTH + " characters");
        }
        return name;
    }

    private static Set<ClientScope> parseScopes(List<String> values) {
        EnumSet<ClientScope> scopes = EnumSet.noneOf(ClientScope.class);
        for (String value : values) {
            String scope = value == null ? "" : value.trim();
            scopes.add(ClientScope.find(scope).orElseThrow(() ->
                    new BadRequestException("Unknown scope '" + scope + "' (allowed: " + allowedScopes() + ")")));
        }
        if (scopes.isEmpty()) {
            throw new BadRequestException("At least one scope is required (" + allowedScopes() + ")");
        }
        return scopes;
    }

    private static String allowedScopes() {
        return String.join(", ", Arrays.stream(ClientScope.values()).map(ClientScope::value).toList());
    }

    private String generateClientId() {
        byte[] bytes = new byte[12];
        random.nextBytes(bytes);
        return "client-" + Base64Url.encode(bytes);
    }

    private String generateSecret() {
        byte[] bytes = new byte[GENERATED_SECRET_BYTES];
        random.nextBytes(bytes);
        return Base64Url.encode(bytes);
    }

    private String newTokenVersion() {
        byte[] bytes = new byte[16];
        random.nextBytes(bytes);
        return Base64Url.encode(bytes);
    }
}
