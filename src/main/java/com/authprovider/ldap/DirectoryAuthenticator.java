package com.authprovider.ldap;

public interface DirectoryAuthenticator {
    DirectoryAuthenticationResult authenticate(String username, String password);
}
