package com.authprovider;

import com.authprovider.entity.User;
import com.authprovider.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {
        "ldap.enabled=true",
        "ldap.base-dn=dc=example,dc=org",
        "ldap.user-search-filter=(&(objectClass=person)(|(uid={0})(sAMAccountName={0})))",
        "ldap.bind-dn=cn=admin,dc=example,dc=org",
        "ldap.bind-password=secret",
        "ldap.auto-provision=true",
        "ldap.fallback-to-local=true"
})
public class LdapFallbackGraderTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    private static final ObjectMapper objectMapper = new ObjectMapper();

    @DynamicPropertySource
    static void configureFallbackProperties(DynamicPropertyRegistry registry) {
        registry.add("ldap.url", () -> "ldap://localhost:" + LdapAuthGraderTest.getMockLdapPort());
    }

    @BeforeEach
    public void resetServer() {
        if (LdapAuthGraderTest.getMockLdapServer() != null) {
            LdapAuthGraderTest.getMockLdapServer().resetState();
        }
    }

    @Test
    @DisplayName("Fallback Policy (true): Local user not in LDAP is allowed to log in via local credentials")
    public void testFallbackPolicy_True_LocalUserAccepted() throws Exception {
        userRepository.findByUsername("localworker")
                .orElseGet(() -> userRepository.save(User.builder()
                        .username("localworker")
                        .password("WorkerLocalPass123!")
                        .build()));

        Map<String, String> request = Map.of(
                "username", "localworker",
                "password", "WorkerLocalPass123!"
        );

        mockMvc.perform(post("/v1/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("Security Trap: Directory user with invalid password must NEVER fall back to local DB credentials")
    public void testFallbackPolicy_True_DirectoryUserBadPassword_NeverFallsBackToLocalDb() throws Exception {
        User bobLocal = userRepository.findByUsername("bob")
                .orElseGet(() -> userRepository.save(User.builder()
                        .username("bob")
                        .password("OldBobLocalPass!")
                        .build()));

        Map<String, String> request = Map.of(
                "username", "bob",
                "password", "OldBobLocalPass!"
        );

        mockMvc.perform(post("/v1/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Fallback Policy (true): Local user with wrong password must be rejected with 401")
    public void testFallbackPolicy_True_LocalUserWrongPassword_Fails() throws Exception {
        userRepository.findByUsername("localworker")
                .orElseGet(() -> userRepository.save(User.builder()
                        .username("localworker")
                        .password("WorkerLocalPass123!")
                        .build()));

        Map<String, String> request = Map.of(
                "username", "localworker",
                "password", "WrongLocalPassword999!"
        );

        mockMvc.perform(post("/v1/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Fallback Policy (true): Non-existent user fails with 401 even with fallback enabled")
    public void testFallbackPolicy_True_NonExistentUser_Fails() throws Exception {
        Map<String, String> request = Map.of(
                "username", "phantom_nobody",
                "password", "Password123!"
        );

        mockMvc.perform(post("/v1/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }
}
