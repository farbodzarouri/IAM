package com.authprovider;

import com.authprovider.entity.User;
import com.authprovider.repository.UserRepository;
import com.authprovider.service.OcraService;
import com.authprovider.service.TotpService;
import com.authprovider.service.UserService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class SecurityAuditRemediationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserService userService;

    @Autowired
    private TotpService totpService;

    @Autowired
    private OcraService ocraService;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    @DisplayName("P0 Access Control: Anonymous caller to /v1/api/users/all is rejected with 401")
    public void testUsersEndpoint_Unauthenticated_ReturnsUnauthorized() throws Exception {
        mockMvc.perform(get("/v1/api/users/all"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("P0 Access Control: Anonymous caller to /v1/api/otp/generate/{id} is rejected with 401")
    public void testOtpGenerate_Unauthenticated_ReturnsUnauthorized() throws Exception {
        mockMvc.perform(post("/v1/api/otp/generate/1"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("P0 Information Exposure: User JSON serialization omits password and 2FA secret")
    public void testUserJsonSerialization_OmitsSensitiveFields() throws Exception {
        User user = User.builder()
                .id(999L)
                .username("auditor")
                .password("supersecretpassword")
                .secret("JBSWY3DPEHPK3PXP")
                .build();

        String json = objectMapper.writeValueAsString(user);
        assertFalse(json.contains("supersecretpassword"), "Serialized JSON must not expose password");
        assertFalse(json.contains("JBSWY3DPEHPK3PXP"), "Serialized JSON must not expose 2FA secret");
        assertTrue(json.contains("auditor"), "Serialized JSON should contain username");
    }

    @Test
    @DisplayName("P1 Credential Storage: Saved user password is automatically BCrypt hashed")
    public void testUserPassword_HashedWithBcrypt() {
        User user = User.builder()
                .username("bcryptuser")
                .password("plainTextPass123")
                .build();

        User saved = userService.saveUser(user);
        assertNotNull(saved.getPassword());
        assertNotEquals("plainTextPass123", saved.getPassword());
        assertTrue(saved.getPassword().startsWith("$2a$") || saved.getPassword().startsWith("$2b$"),
                "Stored password must be a BCrypt hash");
    }

    @Test
    @DisplayName("P2 Identity Collision: Duplicate username registration is prevented")
    public void testDuplicateUsername_Rejected() {
        User first = User.builder().username("uniqueuser").password("pass1").build();
        userService.saveUser(first);

        User duplicate = User.builder().username("uniqueuser").password("pass2").build();
        assertThrows(Exception.class, () -> userService.saveUser(duplicate),
                "Saving duplicate username must fail with exception");
    }

    @Test
    @DisplayName("P3 Cryptography: OCRA constant-time string verification")
    public void testOcraConstantTimeValidation() {
        String secret = "JBSWY3DPEHPK3PXP";
        String challenge = "12345678";
        String validOtp = ocraService.generateOcra(secret, challenge);
        assertNotNull(validOtp);

        assertTrue(ocraService.validateOcra(secret, challenge, validOtp));
        assertFalse(ocraService.validateOcra(secret, challenge, "000000"));
        assertFalse(ocraService.validateOcra(secret, challenge, null));
    }
}
