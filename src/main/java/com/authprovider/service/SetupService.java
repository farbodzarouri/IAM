package com.authprovider.service;

import com.authprovider.entity.Admin;
import com.authprovider.entity.LdapDirectory;

/**
 * Day-0 first-run bootstrap service. Active strictly while no {@link Admin} accounts and no
 * enabled admin {@link LdapDirectory} exist; permanently locks itself as soon as initial setup
 * completes via either local admin creation or Admin LDAP directory registration.
 */
public interface SetupService {

    boolean isSetupRequired();

    Admin initializeLocalAdmin(String username, String password, String displayName);

    LdapDirectory initializeAdminLdap(LdapDirectory directory);
}
