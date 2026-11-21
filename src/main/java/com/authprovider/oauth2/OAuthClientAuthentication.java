package com.authprovider.oauth2;

import com.authprovider.entity.AuthMode;
import com.authprovider.entity.ClientScope;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;
import java.util.Set;

/**
 * Spring Security authentication of a connected system presenting a valid RFC 6750 bearer access token.
 * Granted authorities are {@code SCOPE_<scope>} for each token scope.
 */
public class OAuthClientAuthentication extends AbstractAuthenticationToken {

    /** Authenticated OAuth 2.0 client (as of the token validation). */
    public record Client(Long id, String clientId, String name, AuthMode authMode, Set<ClientScope> scopes,
                         String tokenId) {
    }

    private final Client client;

    public OAuthClientAuthentication(Client client) {
        super(client.scopes().stream().map(s -> new SimpleGrantedAuthority(s.authority())).toList());
        this.client = client;
        setAuthenticated(true);
    }

    /** The OAuth 2.0 client authenticated for the current request, if any. */
    public static Optional<Client> current() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof OAuthClientAuthentication oauth) {
            return Optional.of(oauth.client);
        }
        return Optional.empty();
    }

    public Client client() {
        return client;
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return client.clientId();
    }

    @Override
    public String getName() {
        return client.clientId();
    }
}
