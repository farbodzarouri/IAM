package com.authprovider.radius;

import com.authprovider.config.LdapProperties;
import com.authprovider.entity.User;
import com.authprovider.ldap.DirectoryAuthenticationResult;
import com.authprovider.ldap.DirectoryAuthenticator;
import com.authprovider.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

import static com.authprovider.radius.PrimaryCredentialVerifier.Outcome.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

class PrimaryCredentialVerifierTest {

    private static final String TOTP_SECRET = "JBSWY3DPEHPK3PXP";

    private UserRepository userRepository;
    private DirectoryAuthenticator directory;
    private LdapProperties ldapProperties;
    private PrimaryCredentialVerifier verifier;

    @BeforeEach
    void setUp() {
        userRepository = mock(UserRepository.class);
        directory = mock(DirectoryAuthenticator.class);
        ldapProperties = new LdapProperties();
        ldapProperties.setEnabled(true);
        when(userRepository.findByUsername(anyString())).thenReturn(Optional.empty());
        when(userRepository.findAllByUsernameIgnoreCase(anyString())).thenReturn(List.of());
        verifier = new PrimaryCredentialVerifier(userRepository, new RadiusProperties(), ldapProperties, directory);
    }

    private void localUser(User user) {
        when(userRepository.findByUsername(user.getUsername())).thenReturn(Optional.of(user));
    }

    private static byte[] pw(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void directoryDisabledUsesLocalPasswords() {
        ldapProperties.setEnabled(false);
        localUser(User.builder().id(1L).username("dave").password("pw").secret(TOTP_SECRET).build());

        assertEquals(AUTHENTICATED, verifier.verify("dave", pw("pw"), id -> false).outcome());
        assertEquals(INVALID_CREDENTIALS, verifier.verify("dave", pw("bad"), id -> false).outcome());
        verifyNoInteractions(directory);
    }

    @Test
    void directoryAuthenticatedUserIsLinkedToEnrolledAccount() {
        localUser(User.builder().id(1L).username("alice").secret(TOTP_SECRET).build());
        when(directory.authenticate("alice", "dirpw"))
                .thenReturn(DirectoryAuthenticationResult.authenticated("alice", "uid=alice,dc=example,dc=org"));

        PrimaryCredentialVerifier.Verification result = verifier.verify("CORP\\alice", pw("dirpw"), id -> false);
        assertEquals(AUTHENTICATED, result.outcome());
        assertEquals(1L, result.user().getId());
    }

    @Test
    void directoryUserMustAlreadyBeEnrolled() {
        when(directory.authenticate("bob", "dirpw"))
                .thenReturn(DirectoryAuthenticationResult.authenticated("bob", "uid=bob,dc=example,dc=org"));
        assertEquals(NOT_ENROLLED, verifier.verify("bob", pw("dirpw"), id -> false).outcome());

        localUser(User.builder().id(2L).username("bob").build());
        assertEquals(NOT_ENROLLED, verifier.verify("bob", pw("dirpw"), id -> false).outcome());
        verify(userRepository, never()).save(any());
    }

    @Test
    void invalidDirectoryPasswordNeverFallsBackToLocal() {
        ldapProperties.setFallbackToLocal(true);
        localUser(User.builder().id(3L).username("carol").password("localpw").secret(TOTP_SECRET).build());
        when(directory.authenticate("carol", "localpw")).thenReturn(DirectoryAuthenticationResult.invalidCredentials());

        PrimaryCredentialVerifier.Verification result = verifier.verify("carol", pw("localpw"), id -> false);
        assertEquals(INVALID_CREDENTIALS, result.outcome());
        assertEquals(3L, result.user().getId());
    }

    @Test
    void userUnknownToDirectoryUsesLocalOnlyWhenFallbackEnabled() {
        localUser(User.builder().id(4L).username("local").password("localpw").secret(TOTP_SECRET).build());
        when(directory.authenticate(anyString(), anyString())).thenReturn(DirectoryAuthenticationResult.userNotFound());

        assertEquals(UNKNOWN_USER, verifier.verify("local", pw("localpw"), id -> false).outcome());

        ldapProperties.setFallbackToLocal(true);
        assertEquals(AUTHENTICATED, verifier.verify("local", pw("localpw"), id -> false).outcome());
        assertEquals(INVALID_CREDENTIALS, verifier.verify("local", pw("wrong"), id -> false).outcome());
    }

    @Test
    void directoryOutageIsReported() {
        when(directory.authenticate(anyString(), anyString())).thenReturn(DirectoryAuthenticationResult.unavailable());
        assertEquals(DIRECTORY_UNAVAILABLE, verifier.verify("alice", pw("pw"), id -> false).outcome());

        when(directory.authenticate(anyString(), anyString())).thenThrow(new IllegalStateException("boom"));
        assertEquals(DIRECTORY_UNAVAILABLE, verifier.verify("alice", pw("pw"), id -> false).outcome());
    }

    @Test
    void lockedAccountsDoNotReachTheDirectory() {
        localUser(User.builder().id(5L).username("eve").secret(TOTP_SECRET).build());
        assertEquals(LOCKED, verifier.verify("eve", pw("pw"), id -> id == 5L).outcome());
        verifyNoInteractions(directory);
    }

    @Test
    void emptyPasswordIsNeverSentToTheDirectory() {
        assertEquals(INVALID_CREDENTIALS, verifier.verify("alice", new byte[0], id -> false).outcome());
        verifyNoInteractions(directory);
    }
}
