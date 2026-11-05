package com.authprovider.ldap;

public record DirectoryAuthenticationResult(Status status, String username, String distinguishedName) {

    public enum Status {
        AUTHENTICATED,
        INVALID_CREDENTIALS,
        USER_NOT_FOUND,
        UNAVAILABLE
    }

    public static DirectoryAuthenticationResult authenticated(String username, String distinguishedName) {
        return new DirectoryAuthenticationResult(Status.AUTHENTICATED, username, distinguishedName);
    }

    public static DirectoryAuthenticationResult invalidCredentials() {
        return new DirectoryAuthenticationResult(Status.INVALID_CREDENTIALS, null, null);
    }

    public static DirectoryAuthenticationResult userNotFound() {
        return new DirectoryAuthenticationResult(Status.USER_NOT_FOUND, null, null);
    }

    public static DirectoryAuthenticationResult unavailable() {
        return new DirectoryAuthenticationResult(Status.UNAVAILABLE, null, null);
    }

    public boolean isAuthenticated() {
        return status == Status.AUTHENTICATED;
    }
}
