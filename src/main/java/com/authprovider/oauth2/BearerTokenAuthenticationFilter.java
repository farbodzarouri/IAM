package com.authprovider.oauth2;

import com.authprovider.entity.AuthAuditLog;
import com.authprovider.entity.ClientScope;
import com.authprovider.entity.OAuthClient;
import com.authprovider.service.AuthAuditService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * RFC 6750 bearer token enforcement for the endpoints called by connected systems. Requests to a protected
 * endpoint must carry {@code Authorization: Bearer <access token>} with the endpoint's scope; tokens in query
 * or form parameters are not accepted. On success the request is authenticated as
 * {@link OAuthClientAuthentication} (stateless: no HTTP session is created). Failures are answered with
 * {@code WWW-Authenticate: Bearer} challenges ({@code invalid_request} 400, {@code invalid_token} 401,
 * {@code insufficient_scope} 403) and audited.
 */
@Slf4j
public class BearerTokenAuthenticationFilter extends OncePerRequestFilter {

    public static final String REALM = "iam";
    /** RFC 6750 section 2.1 b64token. */
    private static final Pattern B64TOKEN = Pattern.compile("^[A-Za-z0-9\\-._~+/]+=*$");

    /** A protected endpoint and the scope it requires. */
    public record ProtectedEndpoint(String path, ClientScope scope) {
        RequestMatcher matcher() {
            return AntPathRequestMatcher.antMatcher(path);
        }
    }

    public static final List<ProtectedEndpoint> PROTECTED_ENDPOINTS = List.of(
            new ProtectedEndpoint("/v1/api/auth/login", ClientScope.AUTH_LOGIN),
            new ProtectedEndpoint("/v1/api/otp/validate", ClientScope.OTP_VALIDATE),
            new ProtectedEndpoint("/v1/api/otp/validate-ocra", ClientScope.OTP_VALIDATE),
            new ProtectedEndpoint("/v1/api/mfa/preauth", ClientScope.MFA_PREAUTH));

    private record Matcher(RequestMatcher matcher, ClientScope scope) {
    }

    private final AccessTokenService tokenService;
    private final AuthAuditService auditService;
    private final List<Matcher> matchers;
    private final SecurityContextHolderStrategy contextHolder = SecurityContextHolder.getContextHolderStrategy();

    public BearerTokenAuthenticationFilter(AccessTokenService tokenService, AuthAuditService auditService) {
        this.tokenService = tokenService;
        this.auditService = auditService;
        this.matchers = PROTECTED_ENDPOINTS.stream().map(e -> new Matcher(e.matcher(), e.scope())).toList();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        Optional<ClientScope> required = requiredScope(request);
        if (required.isEmpty()) {
            chain.doFilter(request, response);
            return;
        }
        ClientScope scope = required.get();
        List<String> headers = Collections.list(request.getHeaders(HttpHeaders.AUTHORIZATION));
        if (request.getParameter("access_token") != null) {
            reject(request, response, 400, "invalid_request",
                    "Access tokens are only accepted in the Authorization header", scope, "TOKEN_IN_PARAMETER");
            return;
        }
        if (headers.size() > 1) {
            reject(request, response, 400, "invalid_request", "Multiple Authorization headers", scope,
                    "INVALID_REQUEST");
            return;
        }
        String header = headers.isEmpty() ? null : headers.get(0).strip();
        int space = header == null ? -1 : header.indexOf(' ');
        String schemeName = header == null ? null : (space < 0 ? header : header.substring(0, space));
        if (schemeName == null || !schemeName.toLowerCase(Locale.ROOT).equals("bearer")) {
            reject(request, response, 401, null, "Bearer access token required", scope, "MISSING_TOKEN");
            return;
        }
        String token = space < 0 ? "" : header.substring(space + 1).strip();
        if (token.isEmpty()) {
            reject(request, response, 400, "invalid_request", "Malformed Bearer authorization", scope,
                    "INVALID_REQUEST");
            return;
        }
        if (token.length() > CompactJws.MAX_LENGTH || !B64TOKEN.matcher(token).matches()) {
            reject(request, response, 401, "invalid_token", "The access token is invalid", scope, "MALFORMED_TOKEN");
            return;
        }

        AccessTokenService.Validation validation = tokenService.validate(token);
        if (!validation.isValid()) {
            String clientId = validation.token() == null ? null : validation.token().clientId();
            rejectFor(request, response, 401, "invalid_token", describe(validation.reason()), scope,
                    validation.reason(), clientId);
            return;
        }
        if (!validation.token().scopes().contains(scope)) {
            rejectFor(request, response, 403, "insufficient_scope",
                    "The access token does not grant the '" + scope.value() + "' scope", scope,
                    "INSUFFICIENT_SCOPE", validation.token().clientId());
            return;
        }
        OAuthClient client = validation.client();
        OAuthClientAuthentication authentication = new OAuthClientAuthentication(new OAuthClientAuthentication.Client(
                client.getId(), client.getClientId(), client.getName(), client.getAuthMode(),
                validation.token().scopes(), validation.token().jti()));
        SecurityContext previous = contextHolder.getContext();
        SecurityContext context = contextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        contextHolder.setContext(context);
        try {
            chain.doFilter(request, response);
        } finally {
            contextHolder.setContext(previous);
        }
    }

    private Optional<ClientScope> requiredScope(HttpServletRequest request) {
        for (Matcher matcher : matchers) {
            if (matcher.matcher().matches(request)) {
                return Optional.of(matcher.scope());
            }
        }
        return Optional.empty();
    }

    private static String describe(String reason) {
        if ("TOKEN_EXPIRED".equals(reason)) {
            return "The access token expired";
        }
        if ("TOKEN_REVOKED".equals(reason)) {
            return "The access token has been revoked";
        }
        return "The access token is invalid";
    }

    private void reject(HttpServletRequest request, HttpServletResponse response, int status, String error,
                        String description, ClientScope scope, String reason) throws IOException {
        rejectFor(request, response, status, error, description, scope, reason, null);
    }

    private void rejectFor(HttpServletRequest request, HttpServletResponse response, int status, String error,
                           String description, ClientScope scope, String reason, String clientId) throws IOException {
        auditService.event(AuthAuditLog.Channel.OAUTH2_BEARER, AuthAuditLog.Outcome.FAILURE)
                .username(clientId)
                .clientName(clientId)
                .clientAddress(request.getRemoteAddr())
                .reason(reason)
                .source("OAUTH2")
                .log();
        log.debug("Bearer token rejected for {} ({})", request.getRequestURI(), reason);
        writeChallenge(response, status, error, description, scope);
    }

    /** Writes an RFC 6750 section 3 challenge. */
    public static void writeChallenge(HttpServletResponse response, int status, String error, String description,
                                      ClientScope scope) throws IOException {
        StringBuilder challenge = new StringBuilder("Bearer realm=\"").append(REALM).append('"');
        if (error != null) {
            challenge.append(", error=\"").append(error).append('"');
            if (description != null) {
                challenge.append(", error_description=\"").append(description.replace("\"", "'")).append('"');
            }
        }
        if (scope != null && (error == null || "insufficient_scope".equals(error))) {
            challenge.append(", scope=\"").append(scope.value()).append('"');
        }
        response.resetBuffer();
        response.setStatus(status);
        response.setHeader(HttpHeaders.WWW_AUTHENTICATE, challenge.toString());
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        response.setHeader(HttpHeaders.PRAGMA, "no-cache");
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        String code = error == null ? "unauthorized" : error;
        String body = "{\"error\":\"" + code + "\",\"error_description\":\""
                + (description == null ? "" : description.replace("\\", "\\\\").replace("\"", "'")) + "\"}";
        response.getWriter().write(body);
        response.flushBuffer();
    }
}
