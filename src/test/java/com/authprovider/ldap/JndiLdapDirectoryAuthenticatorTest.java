package com.authprovider.ldap;

import com.authprovider.config.LdapProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.naming.AuthenticationException;
import javax.naming.CommunicationException;
import javax.naming.Context;
import javax.naming.Name;
import javax.naming.NameNotFoundException;
import javax.naming.NamingEnumeration;
import javax.naming.SizeLimitExceededException;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

public class JndiLdapDirectoryAuthenticatorTest {

    private static final String USER_DN = "uid=jdoe,ou=people,dc=example,dc=org";

    private LdapProperties properties;
    private DirContext managerContext;
    private DirContext userContext;
    private final List<Hashtable<String, Object>> environments = new ArrayList<>();

    @BeforeEach
    void setUp() {
        properties = new LdapProperties();
        properties.setEnabled(true);
        managerContext = mock(DirContext.class);
        userContext = mock(DirContext.class);
    }

    private JndiLdapDirectoryAuthenticator authenticator(String validDn, String validPassword) {
        return new JndiLdapDirectoryAuthenticator(properties, env -> {
            environments.add(new Hashtable<>(env));
            Object principal = env.get(Context.SECURITY_PRINCIPAL);
            if (principal == null || principal.equals(properties.getBindDn())) {
                return managerContext;
            }
            if (principal.equals(validDn) && validPassword.equals(env.get(Context.SECURITY_CREDENTIALS))) {
                return userContext;
            }
            throw new AuthenticationException("[LDAP: error code 49 - Invalid Credentials]");
        });
    }

    private static SearchResult result(String dn, String uid) {
        BasicAttributes attributes = new BasicAttributes(true);
        attributes.put("uid", uid);
        SearchResult result = new SearchResult(dn, null, attributes);
        result.setNameInNamespace(dn);
        return result;
    }

    private void searchReturns(NamingEnumeration<SearchResult> results) throws Exception {
        when(managerContext.search(any(Name.class), anyString(), any(Object[].class), any(SearchControls.class)))
                .thenReturn(results);
    }

    @Test
    void searchThenBindSucceedsAndUsesDirectoryCanonicalName() throws Exception {
        searchReturns(new ListEnumeration(List.of(result(USER_DN, "jdoe"))));

        DirectoryAuthenticationResult result = authenticator(USER_DN, "secret").authenticate("JDoe", "secret");

        assertEquals(DirectoryAuthenticationResult.Status.AUTHENTICATED, result.status());
        assertEquals("jdoe", result.username());
        assertEquals(USER_DN, result.distinguishedName());
        verify(managerContext).search(any(Name.class),
                eq("(&(objectClass=person)(|(uid={0})(sAMAccountName={0})))"),
                eq(new Object[]{"JDoe"}), any(SearchControls.class));
        assertEquals("none", environments.get(0).get(Context.SECURITY_AUTHENTICATION));
        assertEquals("simple", environments.get(1).get(Context.SECURITY_AUTHENTICATION));
        assertEquals("ldap://localhost:389", environments.get(1).get(Context.PROVIDER_URL));
        verify(userContext).close();
        verify(managerContext).close();
    }

    @Test
    void usesManagerCredentialsForSearch() throws Exception {
        properties.setBindDn("cn=admin,dc=example,dc=org");
        properties.setBindPassword("adminpw");
        searchReturns(new ListEnumeration(List.of(result(USER_DN, "jdoe"))));

        authenticator(USER_DN, "secret").authenticate("jdoe", "secret");

        assertEquals("cn=admin,dc=example,dc=org", environments.get(0).get(Context.SECURITY_PRINCIPAL));
        assertEquals("adminpw", environments.get(0).get(Context.SECURITY_CREDENTIALS));
    }

    @Test
    void wrongPasswordIsInvalidCredentials() throws Exception {
        searchReturns(new ListEnumeration(List.of(result(USER_DN, "jdoe"))));

        DirectoryAuthenticationResult result = authenticator(USER_DN, "secret").authenticate("jdoe", "wrong");

        assertEquals(DirectoryAuthenticationResult.Status.INVALID_CREDENTIALS, result.status());
    }

    @Test
    void unknownUserIsNotFound() throws Exception {
        searchReturns(new ListEnumeration(List.of()));

        DirectoryAuthenticationResult result = authenticator(USER_DN, "secret").authenticate("ghost", "secret");

        assertEquals(DirectoryAuthenticationResult.Status.USER_NOT_FOUND, result.status());
    }

    @Test
    void ambiguousSearchIsRejected() throws Exception {
        searchReturns(new ListEnumeration(List.of(result(USER_DN, "jdoe"),
                result("uid=jdoe,ou=other,dc=example,dc=org", "jdoe"))));

        assertEquals(DirectoryAuthenticationResult.Status.INVALID_CREDENTIALS,
                authenticator(USER_DN, "secret").authenticate("jdoe", "secret").status());
    }

    @Test
    void sizeLimitExceededIsRejected() throws Exception {
        when(managerContext.search(any(Name.class), anyString(), any(Object[].class), any(SearchControls.class)))
                .thenThrow(new SizeLimitExceededException());

        assertEquals(DirectoryAuthenticationResult.Status.INVALID_CREDENTIALS,
                authenticator(USER_DN, "secret").authenticate("jdoe", "secret").status());
    }

    @Test
    void directoryOutageIsUnavailable() {
        JndiLdapDirectoryAuthenticator authenticator = new JndiLdapDirectoryAuthenticator(properties, env -> {
            throw new CommunicationException("connection refused");
        });

        assertEquals(DirectoryAuthenticationResult.Status.UNAVAILABLE,
                authenticator.authenticate("jdoe", "secret").status());
    }

    @Test
    void emptyPasswordNeverContactsDirectory() {
        JndiLdapDirectoryAuthenticator authenticator = authenticator(USER_DN, "secret");

        assertEquals(DirectoryAuthenticationResult.Status.INVALID_CREDENTIALS,
                authenticator.authenticate("jdoe", "").status());
        assertEquals(DirectoryAuthenticationResult.Status.INVALID_CREDENTIALS,
                authenticator.authenticate("jdoe", null).status());
        assertTrue(environments.isEmpty());
    }

    @Test
    void dnPatternBindsDirectlyWithEscapedUsername() throws Exception {
        properties.setUserDnPattern("uid={0},ou=people,dc=example,dc=org");
        String expectedDn = "uid=evil\\,ou\\=admins,ou=people,dc=example,dc=org";
        when(userContext.getAttributes(any(Name.class), any(String[].class))).thenReturn(new BasicAttributes(true));

        DirectoryAuthenticationResult result = authenticator(expectedDn, "secret").authenticate("evil,ou=admins", "secret");

        assertEquals(DirectoryAuthenticationResult.Status.AUTHENTICATED, result.status());
        assertEquals(expectedDn, result.distinguishedName());
        verifyNoInteractions(managerContext);
    }

    @Test
    void dnPatternFailureWithoutManagerIsTreatedAsPresent() {
        properties.setUserDnPattern("uid={0},ou=people,dc=example,dc=org");

        assertEquals(DirectoryAuthenticationResult.Status.INVALID_CREDENTIALS,
                authenticator(USER_DN, "secret").authenticate("jdoe", "wrong").status());
    }

    @Test
    void dnPatternFailureForMissingEntryIsNotFound() throws Exception {
        properties.setUserDnPattern("uid={0},ou=people,dc=example,dc=org");
        properties.setBindDn("cn=admin,dc=example,dc=org");
        properties.setBindPassword("adminpw");
        when(managerContext.getAttributes(any(Name.class), any(String[].class)))
                .thenThrow(new NameNotFoundException());

        assertEquals(DirectoryAuthenticationResult.Status.USER_NOT_FOUND,
                authenticator(USER_DN, "secret").authenticate("ghost", "wrong").status());
    }

    @Test
    void dnPatternFailureForExistingEntryIsInvalidCredentials() throws Exception {
        properties.setUserDnPattern("uid={0},ou=people,dc=example,dc=org");
        properties.setBindDn("cn=admin,dc=example,dc=org");
        properties.setBindPassword("adminpw");
        when(managerContext.getAttributes(any(Name.class), any(String[].class))).thenReturn(new BasicAttributes(true));

        assertEquals(DirectoryAuthenticationResult.Status.INVALID_CREDENTIALS,
                authenticator(USER_DN, "secret").authenticate("jdoe", "wrong").status());
    }

    @Test
    void configurationValidation() {
        properties.setBindDn("cn=admin,dc=example,dc=org");
        assertThrows(IllegalStateException.class, () -> authenticator(USER_DN, "x").validateConfiguration());

        properties.setBindDn(null);
        properties.setUrl("http://example.org");
        assertThrows(IllegalStateException.class, () -> authenticator(USER_DN, "x").validateConfiguration());

        properties.setUrl("ldaps://ldap.example.org:636");
        properties.setUserSearchFilter("(uid=jdoe)");
        assertThrows(IllegalStateException.class, () -> authenticator(USER_DN, "x").validateConfiguration());

        properties.setUserSearchFilter("(uid={0})");
        assertDoesNotThrow(() -> authenticator(USER_DN, "x").validateConfiguration());

        properties.setEnabled(false);
        properties.setUrl("bogus");
        assertDoesNotThrow(() -> authenticator(USER_DN, "x").validateConfiguration());
    }

    private static final class ListEnumeration implements NamingEnumeration<SearchResult> {
        private final Iterator<SearchResult> iterator;

        ListEnumeration(List<SearchResult> results) {
            this.iterator = results.iterator();
        }

        @Override
        public SearchResult next() {
            if (!iterator.hasNext()) {
                throw new NoSuchElementException();
            }
            return iterator.next();
        }

        @Override
        public boolean hasMore() {
            return iterator.hasNext();
        }

        @Override
        public void close() {
        }

        @Override
        public boolean hasMoreElements() {
            return hasMore();
        }

        @Override
        public SearchResult nextElement() {
            return next();
        }
    }
}
