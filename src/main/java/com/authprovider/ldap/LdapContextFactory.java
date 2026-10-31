package com.authprovider.ldap;

import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import java.util.Hashtable;

@FunctionalInterface
public interface LdapContextFactory {
    DirContext create(Hashtable<String, Object> environment) throws NamingException;
}
