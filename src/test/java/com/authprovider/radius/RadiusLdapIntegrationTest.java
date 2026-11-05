package com.authprovider.radius;

import com.authprovider.LdapAuthTest;
import com.authprovider.entity.User;
import com.authprovider.repository.UserRepository;
import com.authprovider.service.TotpService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static com.authprovider.radius.RadiusConstants.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {
        "radius.port=0",
        "radius.bind-address=127.0.0.1",
        "radius.shared-secret=ldap-radius-secret",
        "ldap.enabled=true",
        "ldap.base-dn=dc=example,dc=org",
        "ldap.user-search-filter=(&(objectClass=person)(|(uid={0})(sAMAccountName={0})))",
        "ldap.bind-dn=cn=admin,dc=example,dc=org",
        "ldap.bind-password=secret",
        "ldap.auto-provision=true",
        "ldap.fallback-to-local=false"
})
@AutoConfigureMockMvc
class RadiusLdapIntegrationTest {

    private static final String SECRET = "ldap-radius-secret";
    private static final String TOTP_SECRET = "JBSWY3DPEHPK3PXP";

    @DynamicPropertySource
    static void ldapUrl(DynamicPropertyRegistry registry) {
        registry.add("ldap.url", () -> "ldap://localhost:" + LdapAuthTest.getMockLdapPort());
    }

    @Autowired
    private RadiusServer radiusServer;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private TotpService totpService;
    @Autowired
    private MockMvc mockMvc;

    private RadiusTestClient client;

    @BeforeEach
    void setUp() throws Exception {
        userRepository.deleteAll();
        client = new RadiusTestClient(radiusServer.getLocalPort(), SECRET);
    }

    @AfterEach
    void tearDown() {
        client.close();
    }

    private String otp(String secret) {
        return String.format("%06d", totpService.generateOtp(secret));
    }

    @Test
    void enrolledDirectoryUserAuthenticatesWithDirectoryPasswordAndOtp() throws Exception {
        userRepository.save(User.builder().username("alice").secret(TOTP_SECRET).build());

        RadiusPacket challenge = client.sendExpectingResponse(client.accessRequest("alice", "Password123!", null));
        assertEquals(ACCESS_CHALLENGE, challenge.getCode());
        byte[] state = challenge.getAttribute(ATTR_STATE).orElseThrow().getValue();

        RadiusPacket accept = client.sendExpectingResponse(client.accessRequest("alice", otp(TOTP_SECRET), state));
        assertEquals(ACCESS_ACCEPT, accept.getCode());
    }

    @Test
    void domainQualifiedDirectoryUserIsResolved() throws Exception {
        userRepository.save(User.builder().username("alice").secret(TOTP_SECRET).build());

        RadiusPacket challenge = client.sendExpectingResponse(client.accessRequest("CONTOSO\\alice", "Password123!", null));
        assertEquals(ACCESS_CHALLENGE, challenge.getCode());
        byte[] state = challenge.getAttribute(ATTR_STATE).orElseThrow().getValue();
        assertEquals(ACCESS_ACCEPT, client.sendExpectingResponse(
                client.accessRequest("CONTOSO\\alice", otp(TOTP_SECRET), state)).getCode());
    }

    @Test
    void wrongDirectoryPasswordIsRejectedEvenIfLocalPasswordMatches() throws Exception {
        userRepository.save(User.builder().username("alice").password("LocalAlicePass!").secret(TOTP_SECRET).build());

        assertEquals(ACCESS_REJECT, client.sendExpectingResponse(
                client.accessRequest("alice", "LocalAlicePass!", null)).getCode());
        assertEquals(ACCESS_REJECT, client.sendExpectingResponse(
                client.accessRequest("alice", "WrongPassword!", null)).getCode());
    }

    @Test
    void directoryUserWithoutLocalAccountIsRejectedAndNotProvisioned() throws Exception {
        assertEquals(ACCESS_REJECT, client.sendExpectingResponse(
                client.accessRequest("bob", "BobLdapPass!", null)).getCode());
        assertTrue(userRepository.findAllByUsernameIgnoreCase("bob").isEmpty(),
                "RADIUS must not just-in-time provision directory users");
    }

    @Test
    void directoryUserNotEnrolledInTwoFactorIsRejected() throws Exception {
        userRepository.save(User.builder().username("bob").build());

        assertEquals(ACCESS_REJECT, client.sendExpectingResponse(
                client.accessRequest("bob", "BobLdapPass!", null)).getCode());
        assertNull(userRepository.findByUsername("bob").orElseThrow().getSecret());
    }

    @Test
    void localOnlyUserIsRejectedWhenFallbackDisabled() throws Exception {
        userRepository.save(User.builder().username("localadmin").password("LocalAdminPass!").secret(TOTP_SECRET).build());

        assertEquals(ACCESS_REJECT, client.sendExpectingResponse(
                client.accessRequest("localadmin", "LocalAdminPass!", null)).getCode());
    }

    @Test
    void outOfBandPreAuthenticationStillWorksWithDirectoryEnabled() throws Exception {
        userRepository.save(User.builder().username("alice").secret(TOTP_SECRET).build());

        mockMvc.perform(post("/v1/api/mfa/preauth").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice\",\"otp\":" + totpService.generateOtp(TOTP_SECRET) + "}"))
                .andExpect(status().isOk()).andExpect(content().string("true"));

        assertEquals(ACCESS_ACCEPT, client.sendExpectingResponse(
                client.accessRequest("alice", null, null)).getCode());
        assertEquals(ACCESS_REJECT, client.sendExpectingResponse(
                client.accessRequest("alice", null, null)).getCode());
    }

    @Test
    void webLoginEnrollmentEnablesRadiusForDirectoryUser() throws Exception {
        mockMvc.perform(post("/v1/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice\",\"password\":\"Password123!\"}"))
                .andExpect(status().isOk());
        String secret = userRepository.findByUsername("alice").orElseThrow().getSecret();
        assertNotNull(secret);

        RadiusPacket challenge = client.sendExpectingResponse(client.accessRequest("alice", "Password123!", null));
        assertEquals(ACCESS_CHALLENGE, challenge.getCode());
        byte[] state = challenge.getAttribute(ATTR_STATE).orElseThrow().getValue();
        assertEquals(ACCESS_ACCEPT, client.sendExpectingResponse(
                client.accessRequest("alice", otp(secret), state)).getCode());
    }
}
