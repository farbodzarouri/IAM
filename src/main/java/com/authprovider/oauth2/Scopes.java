package com.authprovider.oauth2;

import com.authprovider.entity.ClientScope;

import java.util.Collection;
import java.util.EnumSet;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * RFC 6749 section 3.3 scope parameter handling: {@code scope = scope-token *( SP scope-token )} with
 * {@code scope-token = 1*( %x21 / %x23-5B / %x5D-7E )}.
 */
public final class Scopes {

    private Scopes() {
    }

    /**
     * Parses a scope string into known scopes.
     *
     * @throws IllegalArgumentException if the syntax is invalid or a scope is unknown
     */
    public static Set<ClientScope> parse(String value) {
        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException("Empty scope");
        }
        EnumSet<ClientScope> scopes = EnumSet.noneOf(ClientScope.class);
        for (String token : value.split(" ", -1)) {
            if (token.isEmpty() || !isScopeToken(token)) {
                throw new IllegalArgumentException("Malformed scope");
            }
            scopes.add(ClientScope.find(token).orElseThrow(() -> new IllegalArgumentException("Unknown scope")));
        }
        return scopes;
    }

    public static String format(Collection<ClientScope> scopes) {
        if (scopes == null || scopes.isEmpty()) {
            return "";
        }
        return EnumSet.copyOf(scopes).stream().map(ClientScope::value).collect(Collectors.joining(" "));
    }

    private static boolean isScopeToken(String token) {
        for (int i = 0; i < token.length(); i++) {
            char c = token.charAt(i);
            if (c < 0x21 || c > 0x7E || c == 0x22 || c == 0x5C) {
                return false;
            }
        }
        return true;
    }
}
