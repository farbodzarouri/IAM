package com.authprovider.controller;

import com.authprovider.entity.User;
import com.authprovider.ldap.DirectoryAuthenticationResult;
import com.authprovider.ldap.DirectoryAuthenticator;
import com.authprovider.repository.UserRepository;
import com.authprovider.service.TotpService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {"ldap.enabled=true", "ldap.fallback-to-local=false", "ldap.auto-provision=true"})
public class AuthControllerTest {

    private static final String DN = "uid=alice,ou=people,dc=example,dc=org";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TotpService totpService;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private DirectoryAuthenticator directoryAuthenticator;

    @BeforeEach
    void setUp() {
        userRepository.deleteAll();
        when(directoryAuthenticator.authenticate(anyString(), anyString()))
                .thenReturn(DirectoryAuthenticationResult.invalidCredentials());
        when(directoryAuthenticator.authenticate(eq("alice"), eq("correct")))
                .thenReturn(DirectoryAuthenticationResult.authenticated("alice", DN));
        when(directoryAuthenticator.authenticate(eq("ALICE"), eq("correct")))
                .thenReturn(DirectoryAuthenticationResult.authenticated("alice", DN));
    }

    private ResultActions login(String username, String password, String otp) throws Exception {
        StringBuilder json = new StringBuilder("{\"username\":\"").append(username)
                .append("\",\"password\":\"").append(password).append("\"");
        if (otp != null) {
            json.append(",\"otp\":\"").append(otp).append("\"");
        }
        json.append("}");
        return mockMvc.perform(post("/v1/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(json.toString()));
    }

    @Test
    void firstLoginProvisionsUserAndReturnsEnrollment() throws Exception {
        String body = login("alice", "correct", null)
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(jsonPath("$.status").value("ENROLLMENT_REQUIRED"))
                .andExpect(jsonPath("$.username").value("alice"))
                .andReturn().getResponse().getContentAsString();

        JsonNode json = objectMapper.readTree(body);
        String secret = json.get("secret").asText();
        assertFalse(secret.isBlank());
        assertTrue(json.get("otpAuthUri").asText().startsWith("otpauth://totp/IAM:alice?secret=" + secret));
        byte[] png = Base64.getDecoder().decode(json.get("qrCode").asText());
        assertEquals((byte) 0x89, png[0]);
        assertEquals('P', png[1]);

        List<User> users = userRepository.findAll();
        assertEquals(1, users.size());
        assertEquals("alice", users.get(0).getUsername());
        assertEquals(secret, users.get(0).getSecret());
        assertNull(users.get(0).getPassword());
    }

    @Test
    void subsequentLoginRequiresValidTotp() throws Exception {
        String body = login("alice", "correct", null).andReturn().getResponse().getContentAsString();
        String secret = objectMapper.readTree(body).get("secret").asText();

        login("alice", "correct", null)
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value("OTP_REQUIRED"));

        int valid = totpService.generateOtp(secret);
        String wrong = String.format("%06d", (valid + 500000) % 1000000);
        login("alice", "correct", wrong)
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value("INVALID_OTP"));
        login("alice", "correct", "abc")
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value("INVALID_OTP"));

        login("alice", "correct", String.format("%06d", valid))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("AUTHENTICATED"))
                .andExpect(jsonPath("$.authenticated").value(true))
                .andExpect(jsonPath("$.secret").doesNotExist());

        assertEquals(1, userRepository.count());
    }

    @Test
    void usernameCaseVariantsResolveToSameAccount() throws Exception {
        login("alice", "correct", null).andExpect(status().isOk());

        login("ALICE", "correct", null)
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value("OTP_REQUIRED"));
        assertEquals(1, userRepository.count());
    }

    @Test
    void validOtpDoesNotBypassWrongDirectoryPassword() throws Exception {
        String body = login("alice", "correct", null).andReturn().getResponse().getContentAsString();
        String secret = objectMapper.readTree(body).get("secret").asText();

        login("alice", "wrong", String.format("%06d", totpService.generateOtp(secret)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value("INVALID_CREDENTIALS"));
    }

    @Test
    void invalidDirectoryCredentialsNeverFallBackToLocal() throws Exception {
        userRepository.save(User.builder().username("bob").password("localpw").build());

        login("bob", "localpw", null)
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value("INVALID_CREDENTIALS"));
    }

    @Test
    void userAbsentFromDirectoryIsRejectedWhenFallbackDisabled() throws Exception {
        userRepository.save(User.builder().username("carol").password("localpw").build());
        when(directoryAuthenticator.authenticate(eq("carol"), anyString()))
                .thenReturn(DirectoryAuthenticationResult.userNotFound());

        login("carol", "localpw", null)
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value("INVALID_CREDENTIALS"));
    }

    @Test
    void directoryOutageReturnsServiceUnavailable() throws Exception {
        when(directoryAuthenticator.authenticate(eq("alice"), eq("correct")))
                .thenReturn(DirectoryAuthenticationResult.unavailable());

        login("alice", "correct", null)
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.status").value("DIRECTORY_UNAVAILABLE"));
        assertEquals(0, userRepository.count());
    }

    @Test
    void invalidPayloadsAreRejected() throws Exception {
        mockMvc.perform(post("/v1/api/auth/login").contentType(MediaType.APPLICATION_JSON).content("{bad"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value("INVALID_REQUEST"));
        mockMvc.perform(post("/v1/api/auth/login").contentType(MediaType.APPLICATION_JSON).content("{\"username\":\"alice\"}"))
                .andExpect(status().isBadRequest());
        login("alice", "", null).andExpect(status().isBadRequest());
        login(" ", "correct", null).andExpect(status().isBadRequest());
    }
}
