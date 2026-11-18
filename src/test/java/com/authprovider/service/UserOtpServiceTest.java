package com.authprovider.service;

import com.authprovider.dto.OtpValidationResponse;
import com.authprovider.entity.User;
import com.authprovider.exception.ResourceNotFoundException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class UserOtpServiceTest {

    @Mock
    private UserService userService;

    @Mock
    private SecretGenerator secretGenerator;

    @Mock
    private TotpService totpService;

    @Mock
    private OcraService ocraService;

    @InjectMocks
    private UserOtpServiceImpl userOtpService;

    @Test
    public void testGenerateSecretForUser_Success() {
        User user = User.builder().id(1L).username("test").build();
        when(userService.getUserById(1L)).thenReturn(user);
        when(secretGenerator.generateSecret()).thenReturn("JBSWY3DPEHPK3PXP");
        when(userService.saveUser(any(User.class))).thenReturn(user);

        Optional<String> secret = userOtpService.generateSecretForUser(1L);

        assertTrue(secret.isPresent());
        assertEquals("JBSWY3DPEHPK3PXP", secret.get());
    }

    @Test
    public void testGenerateSecretForUsername_NotFoundThrows() {
        when(userService.findAllByUsernameIgnoreCase("missing")).thenReturn(List.of());

        assertThrows(ResourceNotFoundException.class, () -> userOtpService.generateSecretForUsername("missing"));
    }

    @Test
    public void testValidateOtpByUsername_Success() {
        User user = User.builder().id(1L).username("alice").secret("JBSWY3DPEHPK3PXP").build();
        when(userService.findAllByUsernameIgnoreCase("CORP\\alice")).thenReturn(List.of());
        when(userService.findAllByUsernameIgnoreCase("alice")).thenReturn(List.of(user));
        when(totpService.validateOtp("JBSWY3DPEHPK3PXP", 123456)).thenReturn(true);

        OtpValidationResponse response = userOtpService.validateOtpByUsername("CORP\\alice", "123456");

        assertTrue(response.isValid());
        assertEquals(OtpValidationResponse.Status.VALID, response.getStatus());
        assertEquals("alice", response.getUsername());
    }

    @Test
    public void testValidateUserOtp_Success() {
        User user = User.builder().id(1L).secret("JBSWY3DPEHPK3PXP").build();
        when(userService.getUserById(1L)).thenReturn(user);
        when(totpService.validateOtp("JBSWY3DPEHPK3PXP", 123456)).thenReturn(true);

        Optional<Boolean> result = userOtpService.validateUserOtp(1L, 123456);

        assertTrue(result.isPresent());
        assertTrue(result.get());
    }

    @Test
    public void testValidateOcraByUsername_Success() {
        User user = User.builder().id(1L).username("alice").secret("JBSWY3DPEHPK3PXP").build();
        when(userService.findAllByUsernameIgnoreCase("alice")).thenReturn(List.of(user));
        when(ocraService.validateOcra("JBSWY3DPEHPK3PXP", "challenge", "654321")).thenReturn(true);

        OtpValidationResponse response = userOtpService.validateOcraByUsername("alice", "challenge", "654321");

        assertTrue(response.isValid());
        assertEquals(OtpValidationResponse.Status.VALID, response.getStatus());
    }

    @Test
    public void testValidateUserOcra_Success() {
        User user = User.builder().id(1L).secret("JBSWY3DPEHPK3PXP").build();
        when(userService.getUserById(1L)).thenReturn(user);
        when(ocraService.validateOcra("JBSWY3DPEHPK3PXP", "challenge", "654321")).thenReturn(true);

        Optional<Boolean> result = userOtpService.validateUserOcra(1L, "challenge", "654321");

        assertTrue(result.isPresent());
        assertTrue(result.get());
    }
}
