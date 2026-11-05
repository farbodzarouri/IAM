package com.authprovider.service;

import com.authprovider.config.LdapProperties;
import com.authprovider.dto.LoginRequest;
import com.authprovider.dto.LoginResponse;
import com.authprovider.entity.User;
import com.authprovider.ldap.DirectoryAuthenticationResult;
import com.authprovider.ldap.DirectoryAuthenticator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class LoginServiceImplTest {

    private static final String SECRET = "JBSWY3DPEHPK3PXP";

    @Mock
    private DirectoryAuthenticator directoryAuthenticator;
    @Mock
    private UserService userService;
    @Mock
    private SecretGenerator secretGenerator;
    @Mock
    private TotpService totpService;
    @Mock
    private QrCodeGenerator qrCodeGenerator;

    private LdapProperties properties;
    private LoginServiceImpl loginService;

    @BeforeEach
    void setUp() {
        properties = new LdapProperties();
        loginService = new LoginServiceImpl(properties, directoryAuthenticator, userService,
                secretGenerator, totpService, qrCodeGenerator);
    }

    private static LoginRequest request(String username, String password, String otp) {
        return LoginRequest.builder().username(username).password(password).otp(otp).build();
    }

    @Test
    void defaultsMatchSpecification() {
        assertFalse(properties.isEnabled());
        assertEquals("ldap://localhost:389", properties.getUrl());
        assertEquals("dc=example,dc=org", properties.getBaseDn());
        assertEquals("(&(objectClass=person)(|(uid={0})(sAMAccountName={0})))", properties.getUserSearchFilter());
        assertTrue(properties.isAutoProvision());
        assertFalse(properties.isFallbackToLocal());
    }

    @Test
    void ldapDisabledAuthenticatesLocallyWithTotp() {
        User user = User.builder().id(1L).username("dave").password("pw").secret(SECRET).build();
        when(userService.findAllByUsernameIgnoreCase("dave")).thenReturn(List.of(user));
        when(totpService.validateOtp(SECRET, 123456)).thenReturn(true);

        LoginResponse response = loginService.login(request("dave", "pw", "123456"));

        assertEquals(LoginResponse.Status.AUTHENTICATED, response.getStatus());
        assertEquals("LOCAL", response.getAuthenticationSource());
        verifyNoInteractions(directoryAuthenticator);
    }

    @Test
    void ldapDisabledRejectsWrongLocalPassword() {
        User user = User.builder().id(1L).username("dave").password("pw").secret(SECRET).build();
        when(userService.findAllByUsernameIgnoreCase("dave")).thenReturn(List.of(user));

        assertEquals(LoginResponse.Status.INVALID_CREDENTIALS,
                loginService.login(request("dave", "nope", "123456")).getStatus());
        verify(totpService, never()).validateOtp(anyString(), anyInt());
    }

    @Test
    void fallbackToLocalOnlyForUsersAbsentFromDirectory() {
        properties.setEnabled(true);
        properties.setFallbackToLocal(true);
        User user = User.builder().id(2L).username("erin").password("pw").secret(SECRET).build();
        when(directoryAuthenticator.authenticate("erin", "pw")).thenReturn(DirectoryAuthenticationResult.userNotFound());
        when(userService.findAllByUsernameIgnoreCase("erin")).thenReturn(List.of(user));
        when(totpService.validateOtp(SECRET, 654321)).thenReturn(true);

        LoginResponse response = loginService.login(request("erin", "pw", "654321"));
        assertEquals(LoginResponse.Status.AUTHENTICATED, response.getStatus());
        assertEquals("LOCAL", response.getAuthenticationSource());
    }

    @Test
    void fallbackNeverAppliesToDirectoryCredentialFailuresOrOutages() {
        properties.setEnabled(true);
        properties.setFallbackToLocal(true);
        when(directoryAuthenticator.authenticate("frank", "pw"))
                .thenReturn(DirectoryAuthenticationResult.invalidCredentials())
                .thenReturn(DirectoryAuthenticationResult.unavailable());

        assertEquals(LoginResponse.Status.INVALID_CREDENTIALS, loginService.login(request("frank", "pw", null)).getStatus());
        assertEquals(LoginResponse.Status.DIRECTORY_UNAVAILABLE, loginService.login(request("frank", "pw", null)).getStatus());
        verify(userService, never()).findAllByUsernameIgnoreCase(anyString());
    }

    @Test
    void fallbackRejectsProvisionedAccountsWithoutLocalPassword() {
        properties.setEnabled(true);
        properties.setFallbackToLocal(true);
        User user = User.builder().id(3L).username("gina").secret(SECRET).build();
        when(directoryAuthenticator.authenticate("gina", "pw")).thenReturn(DirectoryAuthenticationResult.userNotFound());
        when(userService.findAllByUsernameIgnoreCase("gina")).thenReturn(List.of(user));

        assertEquals(LoginResponse.Status.INVALID_CREDENTIALS, loginService.login(request("gina", "pw", "123456")).getStatus());
    }

    @Test
    void autoProvisionDisabledRejectsUnknownLocalAccount() {
        properties.setEnabled(true);
        properties.setAutoProvision(false);
        when(directoryAuthenticator.authenticate("hank", "pw"))
                .thenReturn(DirectoryAuthenticationResult.authenticated("hank", "uid=hank,dc=example,dc=org"));
        when(userService.findAllByUsernameIgnoreCase("hank")).thenReturn(List.of());

        assertEquals(LoginResponse.Status.NOT_PROVISIONED, loginService.login(request("hank", "pw", null)).getStatus());
        verify(userService, never()).saveUser(any());
    }

    @Test
    void provisioningPersistsSecretAndReturnsEnrollment() throws Exception {
        properties.setEnabled(true);
        when(directoryAuthenticator.authenticate("ivy", "pw"))
                .thenReturn(DirectoryAuthenticationResult.authenticated("ivy", "uid=ivy,dc=example,dc=org"));
        when(userService.findAllByUsernameIgnoreCase("ivy")).thenReturn(List.of());
        when(secretGenerator.generateSecret()).thenReturn(SECRET);
        when(qrCodeGenerator.generateOtpAuthUrl("IAM", "ivy", SECRET)).thenReturn("otpauth://totp/IAM:ivy?secret=" + SECRET);
        when(qrCodeGenerator.generateQrCodeImage(anyString(), anyInt(), anyInt())).thenReturn("cXI=");
        when(userService.saveUser(any(User.class))).thenAnswer(invocation -> {
            User saved = invocation.getArgument(0);
            saved.setId(10L);
            return saved;
        });

        LoginResponse response = loginService.login(request("ivy", "pw", null));

        assertEquals(LoginResponse.Status.ENROLLMENT_REQUIRED, response.getStatus());
        assertEquals(200, response.getHttpStatus());
        assertEquals(10L, response.getUserId());
        assertEquals(SECRET, response.getSecret());
        assertEquals("otpauth://totp/IAM:ivy?secret=" + SECRET, response.getOtpAuthUri());
        assertEquals("cXI=", response.getQrCode());
        verify(userService).saveUser(argThat(u -> "ivy".equals(u.getUsername()) && SECRET.equals(u.getSecret())
                && u.getPassword() == null));
    }

    @Test
    void ambiguousLocalAccountsAreRejected() {
        properties.setEnabled(true);
        when(directoryAuthenticator.authenticate("jack", "pw"))
                .thenReturn(DirectoryAuthenticationResult.authenticated("jack", "uid=jack,dc=example,dc=org"));
        when(userService.findAllByUsernameIgnoreCase("jack")).thenReturn(List.of(
                User.builder().id(1L).username("jack").build(),
                User.builder().id(2L).username("Jack").build()));

        assertEquals(LoginResponse.Status.ACCOUNT_CONFLICT, loginService.login(request("jack", "pw", null)).getStatus());
    }
}
