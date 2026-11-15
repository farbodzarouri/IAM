package com.authprovider.ldap;

import com.authprovider.entity.LdapDirectory;
import com.authprovider.repository.LdapDirectoryRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.naming.AuthenticationException;
import javax.naming.CommunicationException;
import javax.naming.Context;
import javax.naming.NameNotFoundException;
import javax.naming.Name;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class FederatedDirectoryAuthenticatorTest {

    /** url -> (user -> password) */
    private final Map<String, Map<String, String>> users = Map.of(
            "ldap://corp", Map.of("alice", "corp-pw", "shared", "corp-shared"),
            "ldap://partner", Map.of("bob", "partner-pw", "shared", "partner-shared"));
    private final List<String> binds = new ArrayList<>();
    private LdapDirectoryRepository repository;
    private LdapDirectoryService service;
    private FederatedDirectoryAuthenticator federation;
    private boolean partnerDown;

    private static LdapDirectory directory(long id, String name, String realm, int priority, String url) {
        return LdapDirectory.builder().id(id).name(name).realm(realm).priority(priority).url(url)
                .userDnPattern("uid={0},dc=" + name).bindDn("cn=admin,dc=" + name).bindPassword("admin")
                .enabled(true).build();
    }

    @BeforeEach
    void setUp() {
        repository = mock(LdapDirectoryRepository.class);
        LdapDirectory corp = directory(1, "corp", "CORP,corp.example.com", 10, "ldap://corp");
        LdapDirectory partner = directory(2, "partner", "PARTNER", 20, "ldap://partner");
        partner.setFallbackToLocal(true);
        partner.setAutoProvision(false);
        when(repository.findByEnabledTrueOrderByPriorityAscIdAsc()).thenReturn(List.of(corp, partner));
        when(repository.findByName("corp")).thenReturn(Optional.of(corp));
        when(repository.findByName("partner")).thenReturn(Optional.of(partner));
        service = new LdapDirectoryService(repository);
        federation = new FederatedDirectoryAuthenticator(service, env -> {
            String url = (String) env.get(Context.PROVIDER_URL);
            if (partnerDown && url.equals("ldap://partner")) {
                throw new CommunicationException("down");
            }
            String principal = (String) env.get(Context.SECURITY_PRINCIPAL);
            String credentials = (String) env.get(Context.SECURITY_CREDENTIALS);
            DirContext context = mock(DirContext.class);
            if (principal.startsWith("cn=admin")) {
                when(context.getAttributes(any(Name.class), any(String[].class))).thenAnswer(invocation -> {
                    String dn = invocation.getArgument(0).toString();
                    String uid = dn.substring(4, dn.indexOf(','));
                    if (!users.get(url).containsKey(uid)) {
                        throw new NameNotFoundException();
                    }
                    return new BasicAttributes(true);
                });
                return context;
            }
            binds.add(url + " " + principal);
            String uid = principal.substring(4, principal.indexOf(','));
            if (!credentials.equals(users.get(url).get(uid))) {
                throw new AuthenticationException("invalid");
            }
            when(context.getAttributes(any(Name.class), any(String[].class))).thenReturn(new BasicAttributes(true));
            return context;
        });
    }

    @Test
    void qualifiedNamesAreRoutedToTheirRealm() {
        DirectoryAuthenticationResult result = federation.authenticate("PARTNER\\shared", "partner-shared");
        assertTrue(result.isAuthenticated());
        assertEquals("partner", result.directory());
        assertEquals(List.of("ldap://partner uid=shared,dc=partner"), binds);

        binds.clear();
        result = federation.authenticate("shared@corp.example.com", "corp-shared");
        assertTrue(result.isAuthenticated());
        assertEquals("corp", result.directory());
        assertEquals(List.of("ldap://corp uid=shared,dc=corp"), binds);

        // Realm routing is exclusive: the password of another directory is not tried elsewhere.
        assertEquals(DirectoryAuthenticationResult.Status.INVALID_CREDENTIALS,
                federation.authenticate("CORP\\shared", "partner-shared").status());
    }

    @Test
    void unqualifiedNamesAreEvaluatedInPriorityOrder() {
        DirectoryAuthenticationResult bob = federation.authenticate("bob", "partner-pw");
        assertTrue(bob.isAuthenticated());
        assertEquals("partner", bob.directory());
        // DN-pattern directories probe with a bind against a non-existent DN before reporting USER_NOT_FOUND.
        assertEquals(List.of("ldap://corp uid=bob,dc=corp", "ldap://partner uid=bob,dc=partner"), binds);

        binds.clear();
        DirectoryAuthenticationResult shared = federation.authenticate("shared", "partner-shared");
        assertEquals(DirectoryAuthenticationResult.Status.INVALID_CREDENTIALS, shared.status());
        assertEquals(List.of("ldap://corp uid=shared,dc=corp"), binds, "at most one user bind per request");

        assertEquals(DirectoryAuthenticationResult.Status.USER_NOT_FOUND, federation.authenticate("nobody", "x").status());
    }

    @Test
    void unavailableDirectoryFailsClosed() {
        partnerDown = true;
        assertEquals(DirectoryAuthenticationResult.Status.UNAVAILABLE, federation.authenticate("bob", "partner-pw").status());
        assertTrue(federation.authenticate("alice", "corp-pw").isAuthenticated());
    }

    @Test
    void realmQualifiedUnknownRealmFallsBackToUnqualifiedName() {
        assertTrue(federation.authenticateQualified("OTHER\\alice", "alice", "corp-pw").isAuthenticated());
    }

    @Test
    void perDirectoryOptions() {
        assertTrue(service.isEnabled());
        assertTrue(service.isFallbackToLocal("PARTNER\\carol"));
        assertFalse(service.isFallbackToLocal("CORP\\carol"));
        assertFalse(service.isFallbackToLocal("carol"));
        assertTrue(service.isAutoProvision(DirectoryAuthenticationResult.authenticated("a", "dn").withDirectory("corp")));
        assertFalse(service.isAutoProvision(DirectoryAuthenticationResult.authenticated("b", "dn").withDirectory("partner")));
    }

    @Test
    void parsesQualifiedNames() {
        assertEquals(new LdapDirectoryService.QualifiedName("CORP", "alice"), LdapDirectoryService.parse("CORP\\alice"));
        assertEquals(new LdapDirectoryService.QualifiedName("corp.example.com", "alice"),
                LdapDirectoryService.parse(" alice@corp.example.com "));
        assertFalse(LdapDirectoryService.parse("alice").isQualified());
        assertFalse(LdapDirectoryService.parse("alice@").isQualified());
    }
}
