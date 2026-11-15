package com.authprovider.ldap;

public interface DirectoryAuthenticator {

    DirectoryAuthenticationResult authenticate(String username, String password);

    /**
     * @return true if this authenticator routes realm-qualified user names ({@code REALM\\user},
     * {@code user@realm}) itself and should therefore receive them unmodified
     */
    default boolean isRealmAware() {
        return false;
    }

    /**
     * Authenticates a possibly realm-qualified user name. Realm-aware authenticators route the request
     * to the directory matching the realm; if none matches, {@code unqualifiedName} is evaluated across
     * the enabled directories. Other authenticators simply authenticate {@code unqualifiedName}.
     */
    default DirectoryAuthenticationResult authenticateQualified(String qualifiedName, String unqualifiedName,
                                                                String password) {
        return authenticate(unqualifiedName, password);
    }
}
