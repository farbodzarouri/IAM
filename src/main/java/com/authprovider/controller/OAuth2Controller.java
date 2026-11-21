package com.authprovider.controller;

import com.authprovider.config.OAuth2Properties;
import com.authprovider.entity.AuthAuditLog;
import com.authprovider.entity.ClientScope;
import com.authprovider.entity.OAuthClient;
import com.authprovider.oauth2.AccessTokenService;
import com.authprovider.oauth2.ClientAuthenticator;
import com.authprovider.oauth2.RsaJwk;
import com.authprovider.oauth2.Scopes;
import com.authprovider.oauth2.SigningKeyService;
import com.authprovider.oauth2.TokenRevocationStore;
import com.authprovider.service.AuthAuditService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.InvalidMediaTypeException;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * OAuth 2.0 authorization server endpoints for machine-to-machine clients:
 * <ul>
 *     <li>{@code POST /oauth2/token}: {@code client_credentials} grant (RFC 6749 section 4.4) issuing RS256
 *     JWT access tokens (RFC 9068);</li>
 *     <li>{@code POST /oauth2/introspect}: token introspection (RFC 7662);</li>
 *     <li>{@code POST /oauth2/revoke}: token revocation (RFC 7009);</li>
 *     <li>{@code GET /oauth2/jwks}: public JWK Set (RFC 7517).</li>
 * </ul>
 * Token, introspection and revocation requests require HTTP Basic client authentication
 * ({@code client_secret_basic}); parameters must be form-encoded in the request body.
 */
@Slf4j
@RestController
@RequestMapping("/oauth2")
@RequiredArgsConstructor
public class OAuth2Controller {

    static final String GRANT_CLIENT_CREDENTIALS = "client_credentials";
    static final MediaType JWK_SET_MEDIA_TYPE = MediaType.parseMediaType("application/jwk-set+json");
    private static final String BASIC_CHALLENGE = "Basic realm=\"oauth2\", charset=\"UTF-8\"";
    private static final Duration JWKS_MAX_AGE = Duration.ofMinutes(5);

    private final ClientAuthenticator clientAuthenticator;
    private final AccessTokenService tokenService;
    private final TokenRevocationStore revocationStore;
    private final SigningKeyService keyService;
    private final AuthAuditService auditService;
    private final OAuth2Properties properties;

    /** RFC 6749 section 5.2 error. */
    private static final class OAuth2Exception extends RuntimeException {
        private final HttpStatus status;
        private final String error;

        private OAuth2Exception(HttpStatus status, String error, String description) {
            super(description);
            this.status = status;
            this.error = error;
        }
    }

    @PostMapping("/token")
    public ResponseEntity<Map<String, Object>> token(HttpServletRequest request) {
        AuthAuditLog.Channel channel = AuthAuditLog.Channel.OAUTH2_TOKEN;
        try {
            Map<String, String> params = readForm(request);
            OAuthClient client = authenticateClient(request, params, channel);

            String grantType = params.get("grant_type");
            if (grantType == null || grantType.isEmpty()) {
                throw failure(channel, request, client, HttpStatus.BAD_REQUEST, "invalid_request",
                        "Missing grant_type parameter", "INVALID_REQUEST");
            }
            if (!GRANT_CLIENT_CREDENTIALS.equals(grantType)) {
                throw failure(channel, request, client, HttpStatus.BAD_REQUEST, "unsupported_grant_type",
                        "Only the client_credentials grant is supported", "UNSUPPORTED_GRANT_TYPE");
            }
            Set<ClientScope> granted = resolveScopes(request, params, client);
            AccessTokenService.IssuedToken issued = tokenService.issue(client, granted);

            Map<String, Object> body = new LinkedHashMap<>();
            body.put("access_token", issued.value());
            body.put("token_type", "Bearer");
            body.put("expires_in", tokenService.accessTokenTtlSeconds());
            body.put("scope", Scopes.format(granted));
            audit(channel, AuthAuditLog.Outcome.SUCCESS, request, client.getClientId(), "TOKEN_ISSUED");
            log.info("Issued access token {} to OAuth 2.0 client '{}' (scope '{}')", issued.claims().jti(),
                    client.getClientId(), Scopes.format(granted));
            return noStore(ResponseEntity.ok()).contentType(MediaType.APPLICATION_JSON).body(body);
        } catch (OAuth2Exception e) {
            return error(e);
        }
    }

    @PostMapping("/introspect")
    public ResponseEntity<Map<String, Object>> introspect(HttpServletRequest request) {
        AuthAuditLog.Channel channel = AuthAuditLog.Channel.OAUTH2_INTROSPECTION;
        try {
            Map<String, String> params = readForm(request);
            OAuthClient caller = authenticateClient(request, params, channel);
            String token = requireToken(channel, request, caller, params);

            AccessTokenService.Validation validation = tokenService.validate(token);
            Map<String, Object> body = new LinkedHashMap<>();
            String reason = validation.reason();
            if (validation.isValid() && !validation.token().clientId().equals(caller.getClientId())) {
                // Clients may only introspect their own tokens (RFC 7662 section 4, token scanning).
                reason = "FOREIGN_TOKEN";
            }
            if (reason == null) {
                AccessTokenService.AccessToken claims = validation.token();
                body.put("active", true);
                body.put("scope", Scopes.format(claims.scopes()));
                body.put("client_id", claims.clientId());
                body.put("token_type", "Bearer");
                body.put("exp", claims.expiresAt().getEpochSecond());
                body.put("iat", claims.issuedAt().getEpochSecond());
                if (claims.notBefore() != null) {
                    body.put("nbf", claims.notBefore().getEpochSecond());
                }
                body.put("sub", claims.subject());
                body.put("aud", claims.audience().size() == 1 ? claims.audience().get(0) : claims.audience());
                body.put("iss", claims.issuer());
                body.put("jti", claims.jti());
                audit(channel, AuthAuditLog.Outcome.SUCCESS, request, caller.getClientId(), "ACTIVE");
            } else {
                body.put("active", false);
                audit(channel, AuthAuditLog.Outcome.SUCCESS, request, caller.getClientId(), "INACTIVE_" + reason);
            }
            return noStore(ResponseEntity.ok()).contentType(MediaType.APPLICATION_JSON).body(body);
        } catch (OAuth2Exception e) {
            return error(e);
        }
    }

    @PostMapping("/revoke")
    public ResponseEntity<Map<String, Object>> revoke(HttpServletRequest request) {
        AuthAuditLog.Channel channel = AuthAuditLog.Channel.OAUTH2_REVOCATION;
        try {
            Map<String, String> params = readForm(request);
            OAuthClient caller = authenticateClient(request, params, channel);
            String token = requireToken(channel, request, caller, params);

            AccessTokenService.Validation verified = tokenService.verify(token);
            AccessTokenService.AccessToken claims = verified.token();
            if (claims == null || verified.reason() != null) {
                // RFC 7009 section 2.2: invalid (or already expired) tokens do not cause an error.
                audit(channel, AuthAuditLog.Outcome.SUCCESS, request, caller.getClientId(),
                        "IGNORED_" + (verified.reason() == null ? "INVALID_TOKEN" : verified.reason()));
                return noStore(ResponseEntity.ok()).build();
            }
            if (!claims.clientId().equals(caller.getClientId())) {
                throw failure(channel, request, caller, HttpStatus.BAD_REQUEST, "unauthorized_client",
                        "The token was not issued to the requesting client", "FOREIGN_TOKEN");
            }
            boolean revoked = revocationStore.revoke(claims.jti(), claims.clientId(),
                    claims.expiresAt().plusSeconds(properties.getClockSkewSeconds()));
            audit(channel, AuthAuditLog.Outcome.SUCCESS, request, caller.getClientId(),
                    revoked ? "TOKEN_REVOKED" : "ALREADY_REVOKED");
            if (revoked) {
                log.info("OAuth 2.0 client '{}' revoked access token {}", caller.getClientId(), claims.jti());
            }
            return noStore(ResponseEntity.ok()).build();
        } catch (OAuth2Exception e) {
            return error(e);
        }
    }

    @GetMapping("/jwks")
    public ResponseEntity<Map<String, Object>> jwks() {
        List<Map<String, Object>> keys = keyService.publishedKeys().stream().map(RsaJwk::toJson).toList();
        return ResponseEntity.ok()
                .cacheControl(CacheControl.maxAge(JWKS_MAX_AGE).cachePublic())
                .contentType(JWK_SET_MEDIA_TYPE)
                .body(Map.of("keys", keys));
    }

    private OAuthClient authenticateClient(HttpServletRequest request, Map<String, String> params,
                                           AuthAuditLog.Channel channel) {
        if (params.containsKey("client_secret") || params.containsKey("client_assertion")) {
            throw failureFor(channel, request, params.get("client_id"), HttpStatus.UNAUTHORIZED, "invalid_client",
                    "Only HTTP Basic client authentication (client_secret_basic) is supported",
                    "UNSUPPORTED_CLIENT_AUTH");
        }
        List<String> headers = Collections.list(request.getHeaders(HttpHeaders.AUTHORIZATION));
        if (headers.size() > 1) {
            throw failureFor(channel, request, null, HttpStatus.BAD_REQUEST, "invalid_request",
                    "Multiple Authorization headers", "INVALID_REQUEST");
        }
        ClientAuthenticator.Result result = clientAuthenticator.authenticate(headers.isEmpty() ? null : headers.get(0));
        if (!result.isAuthenticated()) {
            AuthAuditLog.Outcome outcome = result.status() == ClientAuthenticator.Status.LOCKED_OUT
                    || result.status() == ClientAuthenticator.Status.CLIENT_BLOCKED || result.newlyLocked()
                    ? AuthAuditLog.Outcome.LOCKED : AuthAuditLog.Outcome.FAILURE;
            String reason = result.newlyLocked() ? "INVALID_SECRET_LOCKED_OUT" : result.status().name();
            audit(channel, outcome, request, result.clientId(), reason);
            throw new OAuth2Exception(HttpStatus.UNAUTHORIZED, "invalid_client", "Client authentication failed");
        }
        String bodyClientId = params.get("client_id");
        if (bodyClientId != null && !bodyClientId.equals(result.client().getClientId())) {
            throw failureFor(channel, request, result.client().getClientId(), HttpStatus.BAD_REQUEST,
                    "invalid_request", "client_id does not match the authenticated client", "CLIENT_ID_MISMATCH");
        }
        return result.client();
    }

    private Set<ClientScope> resolveScopes(HttpServletRequest request, Map<String, String> params,
                                           OAuthClient client) {
        Set<ClientScope> allowed = client.getScopes();
        if (!params.containsKey("scope")) {
            // RFC 6749 section 3.3: omitted scope defaults to the client's registered scopes.
            if (allowed.isEmpty()) {
                throw failure(AuthAuditLog.Channel.OAUTH2_TOKEN, request, client, HttpStatus.BAD_REQUEST,
                        "invalid_scope", "The client has no registered scopes", "INVALID_SCOPE");
            }
            return allowed;
        }
        Set<ClientScope> requested;
        try {
            requested = Scopes.parse(params.get("scope"));
        } catch (IllegalArgumentException e) {
            throw failure(AuthAuditLog.Channel.OAUTH2_TOKEN, request, client, HttpStatus.BAD_REQUEST,
                    "invalid_scope", "The requested scope is invalid or unknown", "INVALID_SCOPE");
        }
        if (!allowed.containsAll(requested)) {
            throw failure(AuthAuditLog.Channel.OAUTH2_TOKEN, request, client, HttpStatus.BAD_REQUEST,
                    "invalid_scope", "The requested scope exceeds the scope granted to the client",
                    "SCOPE_NOT_ALLOWED");
        }
        return requested;
    }

    private String requireToken(AuthAuditLog.Channel channel, HttpServletRequest request, OAuthClient caller,
                                Map<String, String> params) {
        String token = params.get("token");
        if (token == null || token.isEmpty()) {
            throw failure(channel, request, caller, HttpStatus.BAD_REQUEST, "invalid_request",
                    "Missing token parameter", "INVALID_REQUEST");
        }
        return token;
    }

    /**
     * Reads form parameters from the request body only, rejecting query parameters, other content types and
     * repeated parameters (RFC 6749 section 3.1 / 3.2).
     */
    private Map<String, String> readForm(HttpServletRequest request) {
        if (request.getQueryString() != null && !request.getQueryString().isEmpty()) {
            throw new OAuth2Exception(HttpStatus.BAD_REQUEST, "invalid_request",
                    "Parameters must be sent in the form-encoded request body");
        }
        MediaType contentType;
        try {
            contentType = request.getContentType() == null ? null : MediaType.parseMediaType(request.getContentType());
        } catch (InvalidMediaTypeException e) {
            contentType = null;
        }
        if (contentType == null || !MediaType.APPLICATION_FORM_URLENCODED.equalsTypeAndSubtype(contentType)) {
            throw new OAuth2Exception(HttpStatus.BAD_REQUEST, "invalid_request",
                    "Content-Type must be application/x-www-form-urlencoded");
        }
        Map<String, String> params = new LinkedHashMap<>();
        for (Map.Entry<String, String[]> entry : request.getParameterMap().entrySet()) {
            String[] values = entry.getValue();
            if (values == null || values.length != 1) {
                throw new OAuth2Exception(HttpStatus.BAD_REQUEST, "invalid_request",
                        "Parameter '" + entry.getKey() + "' must not be repeated");
            }
            params.put(entry.getKey(), values[0]);
        }
        return params;
    }

    private OAuth2Exception failure(AuthAuditLog.Channel channel, HttpServletRequest request, OAuthClient client,
                                    HttpStatus status, String error, String description, String reason) {
        return failureFor(channel, request, client == null ? null : client.getClientId(), status, error, description,
                reason);
    }

    private OAuth2Exception failureFor(AuthAuditLog.Channel channel, HttpServletRequest request, String clientId,
                                       HttpStatus status, String error, String description, String reason) {
        audit(channel, AuthAuditLog.Outcome.FAILURE, request, clientId, reason);
        return new OAuth2Exception(status, error, description);
    }

    private void audit(AuthAuditLog.Channel channel, AuthAuditLog.Outcome outcome, HttpServletRequest request,
                       String clientId, String reason) {
        auditService.event(channel, outcome)
                .username(clientId)
                .clientName(clientId)
                .clientAddress(request.getRemoteAddr())
                .reason(reason)
                .source("OAUTH2")
                .log();
    }

    private static ResponseEntity<Map<String, Object>> error(OAuth2Exception e) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", e.error);
        if (e.getMessage() != null) {
            body.put("error_description", e.getMessage());
        }
        ResponseEntity.BodyBuilder builder = noStore(ResponseEntity.status(e.status));
        if (e.status == HttpStatus.UNAUTHORIZED) {
            builder.header(HttpHeaders.WWW_AUTHENTICATE, BASIC_CHALLENGE);
        }
        return builder.contentType(MediaType.APPLICATION_JSON).body(body);
    }

    private static ResponseEntity.BodyBuilder noStore(ResponseEntity.BodyBuilder builder) {
        return builder.cacheControl(CacheControl.noStore()).header(HttpHeaders.PRAGMA, "no-cache");
    }
}
