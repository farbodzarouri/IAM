package com.authprovider.ldap;

import com.authprovider.config.LdapProperties;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.InvalidNameException;
import javax.naming.NameNotFoundException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.NamingSecurityException;
import javax.naming.PartialResultException;
import javax.naming.SizeLimitExceededException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
import java.util.Locale;

@Slf4j
@Component
public class JndiLdapDirectoryAuthenticator implements DirectoryAuthenticator {

    static final String LDAP_CONTEXT_FACTORY = "com.sun.jndi.ldap.LdapCtxFactory";
    static final String CONNECT_TIMEOUT_PROPERTY = "com.sun.jndi.ldap.connect.timeout";
    static final String READ_TIMEOUT_PROPERTY = "com.sun.jndi.ldap.read.timeout";
    private static final String USERNAME_PLACEHOLDER = "{0}";
    private static final String NO_ATTRIBUTES = "1.1";

    private final LdapProperties properties;
    private final LdapContextFactory contextFactory;

    @Autowired
    public JndiLdapDirectoryAuthenticator(LdapProperties properties) {
        this(properties, InitialDirContext::new);
    }

    public JndiLdapDirectoryAuthenticator(LdapProperties properties, LdapContextFactory contextFactory) {
        this.properties = properties;
        this.contextFactory = contextFactory;
    }

    @PostConstruct
    public void validateConfiguration() {
        if (!properties.isEnabled()) {
            return;
        }
        if (!hasText(properties.getUrl())) {
            throw new IllegalStateException("ldap.url must be set when ldap.enabled=true");
        }
        for (String url : properties.getUrl().trim().split("\\s+")) {
            String lower = url.toLowerCase(Locale.ROOT);
            if (!lower.startsWith("ldap://") && !lower.startsWith("ldaps://")) {
                throw new IllegalStateException("ldap.url must use the ldap:// or ldaps:// scheme: " + url);
            }
            if (lower.startsWith("ldap://")) {
                log.warn("LDAP URL {} is not using TLS; credentials will be sent in clear text. Use ldaps:// in production.", url);
            }
        }
        if (hasText(properties.getBindDn()) && !hasText(properties.getBindPassword())) {
            throw new IllegalStateException("ldap.bind-password must be set when ldap.bind-dn is configured");
        }
        if (hasText(properties.getUserDnPattern())) {
            if (!properties.getUserDnPattern().contains(USERNAME_PLACEHOLDER)) {
                throw new IllegalStateException("ldap.user-dn-pattern must contain the {0} placeholder");
            }
        } else {
            if (!hasText(properties.getUserSearchFilter()) || !properties.getUserSearchFilter().contains(USERNAME_PLACEHOLDER)) {
                throw new IllegalStateException("ldap.user-search-filter must contain the {0} placeholder");
            }
            try {
                new LdapName(nullToEmpty(properties.getBaseDn()));
            } catch (InvalidNameException e) {
                throw new IllegalStateException("ldap.base-dn is not a valid distinguished name", e);
            }
        }
    }

    @Override
    public DirectoryAuthenticationResult authenticate(String username, String password) {
        if (!hasText(username) || password == null || password.isEmpty()) {
            return DirectoryAuthenticationResult.invalidCredentials();
        }
        if (hasText(properties.getUserDnPattern())) {
            return authenticateWithDnPattern(username, password);
        }
        return authenticateWithSearch(username, password);
    }

    private DirectoryAuthenticationResult authenticateWithSearch(String username, String password) {
        String userDn;
        String canonicalUsername;
        DirContext managerContext = null;
        NamingEnumeration<SearchResult> results = null;
        try {
            managerContext = openContext(properties.getBindDn(), properties.getBindPassword());
            results = managerContext.search(
                    new LdapName(nullToEmpty(properties.getBaseDn())),
                    properties.getUserSearchFilter(),
                    new Object[]{username},
                    searchControls());
            List<SearchResult> matches = new ArrayList<>();
            try {
                while (results.hasMore()) {
                    matches.add(results.next());
                }
            } catch (PartialResultException e) {
                log.debug("Ignoring unresolved referral during directory search: {}", e.getMessage());
            }
            if (matches.isEmpty()) {
                return DirectoryAuthenticationResult.userNotFound();
            }
            if (matches.size() > 1) {
                log.warn("Directory search returned multiple entries for a single login name; rejecting authentication");
                return DirectoryAuthenticationResult.invalidCredentials();
            }
            SearchResult match = matches.get(0);
            userDn = match.getNameInNamespace();
            canonicalUsername = canonicalUsername(match.getAttributes(), username);
        } catch (SizeLimitExceededException e) {
            log.warn("Directory search returned multiple entries for a single login name; rejecting authentication");
            return DirectoryAuthenticationResult.invalidCredentials();
        } catch (NamingException e) {
            log.error("Directory user search failed: {}", e.toString());
            return DirectoryAuthenticationResult.unavailable();
        } finally {
            close(results);
            close(managerContext);
        }
        return bindAsUser(userDn, password, canonicalUsername);
    }

    private DirectoryAuthenticationResult bindAsUser(String userDn, String password, String canonicalUsername) {
        DirContext userContext = null;
        try {
            userContext = openContext(userDn, password);
            return DirectoryAuthenticationResult.authenticated(canonicalUsername, userDn);
        } catch (NamingSecurityException e) {
            log.info("Directory bind rejected for {}", userDn);
            return DirectoryAuthenticationResult.invalidCredentials();
        } catch (NamingException e) {
            log.error("Directory bind failed for {}: {}", userDn, e.toString());
            return DirectoryAuthenticationResult.unavailable();
        } finally {
            close(userContext);
        }
    }

    private DirectoryAuthenticationResult authenticateWithDnPattern(String username, String password) {
        String userDn = properties.getUserDnPattern().replace(USERNAME_PLACEHOLDER, Rdn.escapeValue(username));
        DirContext userContext = null;
        try {
            userContext = openContext(userDn, password);
            String canonicalUsername = readCanonicalUsername(userContext, userDn, username);
            return DirectoryAuthenticationResult.authenticated(canonicalUsername, userDn);
        } catch (AuthenticationException e) {
            if (isKnownToBeAbsent(userDn)) {
                return DirectoryAuthenticationResult.userNotFound();
            }
            log.info("Directory bind rejected for {}", userDn);
            return DirectoryAuthenticationResult.invalidCredentials();
        } catch (NamingSecurityException e) {
            log.info("Directory bind rejected for {}", userDn);
            return DirectoryAuthenticationResult.invalidCredentials();
        } catch (NamingException e) {
            log.error("Directory bind failed for {}: {}", userDn, e.toString());
            return DirectoryAuthenticationResult.unavailable();
        } finally {
            close(userContext);
        }
    }

    private boolean isKnownToBeAbsent(String userDn) {
        if (!hasText(properties.getBindDn())) {
            return false;
        }
        LdapName name;
        try {
            name = new LdapName(userDn);
        } catch (InvalidNameException e) {
            return false;
        }
        DirContext managerContext = null;
        try {
            managerContext = openContext(properties.getBindDn(), properties.getBindPassword());
            managerContext.getAttributes(name, new String[]{NO_ATTRIBUTES});
            return false;
        } catch (NameNotFoundException e) {
            return true;
        } catch (NamingException e) {
            log.warn("Unable to determine directory presence of {}: {}", userDn, e.toString());
            return false;
        } finally {
            close(managerContext);
        }
    }

    private String readCanonicalUsername(DirContext context, String userDn, String fallback) {
        try {
            Attributes attributes = context.getAttributes(new LdapName(userDn), usernameAttributes());
            return canonicalUsername(attributes, fallback);
        } catch (NamingException e) {
            return fallback;
        }
    }

    private String canonicalUsername(Attributes attributes, String fallback) throws NamingException {
        if (attributes == null) {
            return fallback;
        }
        String first = null;
        for (String attributeName : usernameAttributes()) {
            Attribute attribute = attributes.get(attributeName);
            if (attribute == null) {
                continue;
            }
            NamingEnumeration<?> values = attribute.getAll();
            try {
                while (values.hasMore()) {
                    Object value = values.next();
                    if (value instanceof String text && hasText(text)) {
                        String trimmed = text.trim();
                        if (trimmed.equalsIgnoreCase(fallback)) {
                            return trimmed;
                        }
                        if (first == null) {
                            first = trimmed;
                        }
                    }
                }
            } finally {
                close(values);
            }
        }
        return first != null ? first : fallback;
    }

    private SearchControls searchControls() {
        SearchControls controls = new SearchControls();
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        controls.setCountLimit(2);
        controls.setReturningAttributes(usernameAttributes());
        controls.setDerefLinkFlag(false);
        controls.setReturningObjFlag(false);
        if (properties.getReadTimeoutMs() > 0) {
            controls.setTimeLimit(properties.getReadTimeoutMs());
        }
        return controls;
    }

    private String[] usernameAttributes() {
        List<String> names = properties.getUsernameAttributes();
        if (names == null || names.isEmpty()) {
            return new String[]{NO_ATTRIBUTES};
        }
        return names.stream().filter(JndiLdapDirectoryAuthenticator::hasText).map(String::trim).toArray(String[]::new);
    }

    private DirContext openContext(String principal, String credentials) throws NamingException {
        Hashtable<String, Object> environment = new Hashtable<>();
        environment.put(Context.INITIAL_CONTEXT_FACTORY, LDAP_CONTEXT_FACTORY);
        environment.put(Context.PROVIDER_URL, properties.getUrl().trim());
        if (hasText(properties.getReferral())) {
            environment.put(Context.REFERRAL, properties.getReferral().trim());
        }
        if (properties.getConnectTimeoutMs() > 0) {
            environment.put(CONNECT_TIMEOUT_PROPERTY, String.valueOf(properties.getConnectTimeoutMs()));
        }
        if (properties.getReadTimeoutMs() > 0) {
            environment.put(READ_TIMEOUT_PROPERTY, String.valueOf(properties.getReadTimeoutMs()));
        }
        if (hasText(principal)) {
            if (credentials == null || credentials.isEmpty()) {
                throw new AuthenticationException("Refusing unauthenticated simple bind");
            }
            environment.put(Context.SECURITY_AUTHENTICATION, "simple");
            environment.put(Context.SECURITY_PRINCIPAL, principal);
            environment.put(Context.SECURITY_CREDENTIALS, credentials);
        } else {
            environment.put(Context.SECURITY_AUTHENTICATION, "none");
        }
        return contextFactory.create(environment);
    }

    private static void close(DirContext context) {
        if (context != null) {
            try {
                context.close();
            } catch (NamingException e) {
                log.debug("Failed to close directory context: {}", e.toString());
            }
        }
    }

    private static void close(NamingEnumeration<?> enumeration) {
        if (enumeration != null) {
            try {
                enumeration.close();
            } catch (NamingException e) {
                log.debug("Failed to close directory enumeration: {}", e.toString());
            }
        }
    }

    private static boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value.trim();
    }
}
