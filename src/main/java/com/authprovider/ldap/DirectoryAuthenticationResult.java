package com.authprovider.ldap;

/**
 * Outcome of a directory bind. {@code directory} names the federated directory that produced the
 * result (may be {@code null} for single-directory authenticators).
 */
public record DirectoryAuthenticationResult(Status status, String username, String distinguishedName, String directory) {

    public enum Status {
        AUTHENTICATED,
        INVALID_CREDENTIALS,
        USER_NOT_FOUND,
        UNAVAILABLE
    }

    public DirectoryAuthenticationResult(Status status, String username, String distinguishedName) {
        this(status, username, distinguishedName, null);
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

    public DirectoryAuthenticationResult withDirectory(String directoryName) {
        return new DirectoryAuthenticationResult(status, username, distinguishedName, directoryName);
    }

    public boolean isAuthenticated() {
        return status == Status.AUTHENTICATED;
    }
}
