package com.authprovider;

import com.authprovider.entity.AuthMode;
import com.authprovider.entity.ClientScope;
import com.authprovider.entity.OAuthClient;
import com.authprovider.oauth2.AccessTokenService;
import com.authprovider.repository.OAuthClientRepository;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpHeaders;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.web.context.support.WebApplicationContextUtils;

import java.util.EnumSet;
import java.util.Set;
import java.util.UUID;

/**
 * Test helper attaching a valid RFC 6750 bearer access token of a registered connected-system client to
 * MockMvc requests targeting the OAuth 2.0 protected endpoints.
 */
public final class OAuthTestSupport {

    public static final String TEST_CLIENT_ID = "test-connected-system";
    public static final String TEST_CLIENT_SECRET = "test-connected-system-secret";
    private static volatile String secretHash;

    private OAuthTestSupport() {
    }

    /** Bearer token with all scopes for a client without an {@link AuthMode} override. */
    public static RequestPostProcessor bearer() {
        return bearer(TEST_CLIENT_ID, null, EnumSet.allOf(ClientScope.class));
    }

    /** Bearer token of a dedicated client with the given auth mode override and scopes. */
    public static RequestPostProcessor bearer(String clientId, AuthMode authMode, Set<ClientScope> scopes) {
        return request -> {
            ApplicationContext context = WebApplicationContextUtils
                    .getRequiredWebApplicationContext(request.getServletContext());
            request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + issueToken(context, clientId, authMode, scopes));
            return request;
        };
    }

    /**
     * Bearer token of a dedicated client <em>without</em> assigning any user to it (users need an enabled
     * assignment to the client to authenticate through it).
     */
    public static RequestPostProcessor bearerWithoutAssignments(String clientId, AuthMode authMode,
                                                                Set<ClientScope> scopes) {
        return request -> {
            ApplicationContext context = WebApplicationContextUtils
                    .getRequiredWebApplicationContext(request.getServletContext());
            OAuthClient client = ensureClient(context, clientId, authMode, scopes);
            request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer "
                    + context.getBean(AccessTokenService.class).issue(client, scopes).value());
            return request;
        };
    }

    /**
     * Issues a token for the client. Every existing user without an assignment to a client is assigned to it
     * (enabled, inheriting the client mode), so tests not concerned with assignments can authenticate.
     */
    public static String issueToken(ApplicationContext context, String clientId, AuthMode authMode,
                                    Set<ClientScope> scopes) {
        OAuthClient client = ensureClient(context, clientId, authMode, scopes);
        context.getBean(TestClientAssignments.class).assignAll();
        return context.getBean(AccessTokenService.class).issue(client, scopes).value();
    }

    public static OAuthClient ensureClient(ApplicationContext context, String clientId, AuthMode authMode,
                                           Set<ClientScope> scopes) {
        OAuthClientRepository repository = context.getBean(OAuthClientRepository.class);
        OAuthClient client = repository.findByClientId(clientId).orElseGet(() -> OAuthClient.builder()
                .clientId(clientId)
                .name(clientId)
                .clientSecretHash(hash())
                .tokenVersion(UUID.randomUUID().toString())
                .build());
        if (client.getId() == null || !client.isEnabled() || client.isBlocked() || client.getAuthMode() != authMode
                || !client.getScopes().equals(scopes)) {
            client.setEnabled(true);
            client.setBlocked(false);
            client.setAuthMode(authMode);
            client.setScopes(EnumSet.copyOf(scopes));
            client = repository.saveAndFlush(client);
        }
        return client;
    }

    private static String hash() {
        String hash = secretHash;
        if (hash == null) {
            hash = new BCryptPasswordEncoder().encode(TEST_CLIENT_SECRET);
            secretHash = hash;
        }
        return hash;
    }
}
