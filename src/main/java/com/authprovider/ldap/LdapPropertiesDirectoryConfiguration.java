package com.authprovider.ldap;

import com.authprovider.config.LdapProperties;

/** {@link DirectoryConfiguration} backed by the (single directory) {@code ldap.*} properties. */
public class LdapPropertiesDirectoryConfiguration implements DirectoryConfiguration {

    private final LdapProperties properties;

    public LdapPropertiesDirectoryConfiguration(LdapProperties properties) {
        this.properties = properties;
    }

    @Override
    public boolean isEnabled() {
        return properties != null && properties.isEnabled();
    }

    @Override
    public boolean isFallbackToLocal(String username) {
        return properties != null && properties.isFallbackToLocal();
    }

    @Override
    public boolean isAutoProvision(DirectoryAuthenticationResult result) {
        return properties != null && properties.isAutoProvision();
    }
}
