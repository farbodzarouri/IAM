package com.authprovider.ldap;

/**
 * Directory federation settings consulted by the login flows.
 */
public interface DirectoryConfiguration {

    /** @return true if at least one directory is enabled (directory authentication is in effect). */
    boolean isEnabled();

    /**
     * @return true if a user unknown to the directories responsible for {@code username} may be
     * authenticated against the local user store
     */
    boolean isFallbackToLocal(String username);

    /** @return true if a local account may be provisioned for a successfully authenticated directory user. */
    boolean isAutoProvision(DirectoryAuthenticationResult result);

    /** @return true if at least one directory is enabled for administrator authentication. */
    default boolean isAdminEnabled() {
        return false;
    }

    /**
     * @return true if an admin unknown to the admin directories responsible for {@code username} may
     * authenticate against the local admin store
     */
    default boolean isAdminFallbackToLocal(String username) {
        return isFallbackToLocal(username);
    }

    /** @return true if a local admin record may be provisioned for a successfully authenticated directory admin. */
    default boolean isAdminAutoProvision(DirectoryAuthenticationResult result) {
        return isAutoProvision(result);
    }
}
