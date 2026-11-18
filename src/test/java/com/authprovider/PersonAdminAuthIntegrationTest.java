package com.authprovider;

import com.authprovider.config.DatabaseConfigurationBootstrap;
import com.authprovider.entity.Admin;
import com.authprovider.entity.LdapDirectory;
import com.authprovider.entity.OtpToken;
import com.authprovider.entity.Person;
import com.authprovider.entity.RadiusClient;
import com.authprovider.entity.SecurityPolicy;
import com.authprovider.entity.User;
import com.authprovider.radius.RadiusAttribute;
import com.authprovider.radius.RadiusConstants;
import com.authprovider.radius.RadiusCrypto;
import com.authprovider.radius.RadiusPacket;
import com.authprovider.radius.RadiusServer;
import com.authprovider.repository.AdminRepository;
import com.authprovider.repository.AuthFailureRecordRepository;
import com.authprovider.repository.LdapDirectoryRepository;
import com.authprovider.repository.MfaApprovalRepository;
import com.authprovider.repository.OcraChallengeUseRepository;
import com.authprovider.repository.OtpReplayStateRepository;
import com.authprovider.repository.OtpTokenRepository;
import com.authprovider.repository.PersonRepository;
import com.authprovider.repository.RadiusChallengeSessionRepository;
import com.authprovider.repository.RadiusClientRepository;
import com.authprovider.repository.SecurityPolicyRepository;
import com.authprovider.repository.UserRepository;
import com.authprovider.service.AccountLockoutService;
import com.authprovider.service.PersonService;
import com.authprovider.service.SecretGenerator;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.binary.Base32;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(properties = {
        "radius.port=0",
        "radius.bind-address=127.0.0.1",
        "iam.bootstrap.radius.shared-secret=stage1-secret",
        "iam.bootstrap.policy.max-failures=3",
        "iam.bootstrap.policy.lockout-seconds=120",
        "iam.bootstrap.policy.mfa-approval-ttl-seconds=60",
        "iam.bootstrap.policy.challenge-ttl-seconds=60",
        "iam.bootstrap.admin.username=admin",
        "iam.bootstrap.admin.password=admin-change-me"
})
@AutoConfigureMockMvc
class PersonAdminAuthIntegrationTest {

    private static final String RADIUS_SECRET = "stage1-secret";
    private static final String USER_PASS = "UserPass!123";
    private static final String ADMIN_PASS = "AdminPass!456";
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base32 BASE32 = new Base32();
    private static final ObjectMapper JSON = new ObjectMapper();

    @Autowired private MockMvc mockMvc;
    @Autowired private DatabaseConfigurationBootstrap bootstrap;
    @Autowired private PersonService personService;
    @Autowired private AccountLockoutService lockoutService;
    @Autowired private SecretGenerator secretGenerator;
    @Autowired private RadiusServer radiusServer;
    @Autowired private PersonRepository personRepository;
    @Autowired private OtpTokenRepository otpTokenRepository;
    @Autowired private AdminRepository adminRepository;
    @Autowired private UserRepository userRepository;
    @Autowired private AuthFailureRecordRepository failureRepository;
    @Autowired private MfaApprovalRepository approvalRepository;
    @Autowired private RadiusChallengeSessionRepository challengeRepository;
    @Autowired private RadiusClientRepository radiusClientRepository;
    @Autowired private OtpReplayStateRepository replayRepository;
    @Autowired private OcraChallengeUseRepository ocraRepository;
    @Autowired private LdapDirectoryRepository ldapDirectoryRepository;
    @Autowired private SecurityPolicyRepository policyRepository;
    @Autowired private Clock clock;

    private final AtomicInteger radiusIdSeq = new AtomicInteger(1);

    @BeforeEach
    void setUp() {
        cleanAllAndReseed();
        configurePolicy(3, 3, 120, 300, 300);
    }

    @AfterEach
    void tearDown() {
        cleanAllAndReseed();
        configurePolicy(3, 3, 120, 300, 300);
    }

    private void cleanAllAndReseed() {
        challengeRepository.deleteAll();
        approvalRepository.deleteAll();
        failureRepository.deleteAll();
        replayRepository.deleteAll();
        ocraRepository.deleteAll();
        userRepository.deleteAll();
        adminRepository.deleteAll();
        otpTokenRepository.deleteAll();
        personRepository.deleteAll();
        radiusClientRepository.findAll().stream()
                .filter(c -> !c.getName().startsWith("default"))
                .forEach(radiusClientRepository::delete);
        ldapDirectoryRepository.deleteAll();
        ldapDirectoryRepository.flush();
        bootstrap.seed();
    }

    private void configurePolicy(int maxFailures, int mfaMaxFailures, long lockoutSeconds,
                                 long failureWindowSeconds, long mfaLockoutWindowSeconds) {
        SecurityPolicy policy = policyRepository.findByName(SecurityPolicy.DEFAULT_NAME).orElseThrow();
        policy.setMaxFailures(maxFailures);
        policy.setMfaMaxFailedAttempts(mfaMaxFailures);
        policy.setLockoutSeconds(lockoutSeconds);
        policy.setFailureWindowSeconds(failureWindowSeconds);
        policy.setMfaLockoutWindowSeconds(mfaLockoutWindowSeconds);
        policy.setChallengeTtlSeconds(60);
        policy.setChallengeMaxPending(10_000);
        policy.setRequireMessageAuthenticator(false);
        policy.setStripRealm(true);
        policy.setChallengePrompt("Enter your one-time passcode");
        policy.setMfaOutOfBandEnabled(true);
        policyRepository.saveAndFlush(policy);
    }

    private long stableCurrentStep() throws InterruptedException {
        while (clock.millis() % 30_000L > 22_000L) {
            Thread.sleep(200);
        }
        return clock.millis() / 30_000L;
    }

    private String distinctSecret(long step) {
        for (int attempt = 0; attempt < 50; attempt++) {
            String candidate = secretGenerator.generateSecret();
            String cPrev = otpForStep(candidate, step - 1);
            String cCurr = otpForStep(candidate, step);
            String cNext = otpForStep(candidate, step + 1);
            if (!cPrev.equals(cCurr) && !cCurr.equals(cNext) && !cPrev.equals(cNext)) {
                return candidate;
            }
        }
        return "JBSWY3DPEHPK3PXP";
    }

    private static String otpForStep(String secret, long step) {
        try {
            byte[] key = BASE32.decode(secret);
            byte[] data = new byte[8];
            long value = step;
            for (int i = 8; i-- > 0; value >>>= 8) {
                data[i] = (byte) value;
            }
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key, "HmacSHA1"));
            byte[] hash = mac.doFinal(data);
            int offset = hash[hash.length - 1] & 0xF;
            long binary = ((hash[offset] & 0x7fL) << 24)
                    | ((hash[offset + 1] & 0xffL) << 16)
                    | ((hash[offset + 2] & 0xffL) << 8)
                    | (hash[offset + 3] & 0xffL);
            return String.format("%06d", (int) (binary % 1_000_000L));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to compute RFC 6238 TOTP", e);
        }
    }

    private static String wrongOtpForStep(String secret, long step) {
        Set<String> valid = Set.of(
                otpForStep(secret, step - 1),
                otpForStep(secret, step),
                otpForStep(secret, step + 1));
        int candidate = 100001;
        while (valid.contains(String.format("%06d", candidate))) {
            candidate++;
        }
        return String.format("%06d", candidate);
    }

    private JsonNode postLogin(String endpoint, String username, String password, String otp) throws Exception {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"username\":\"").append(escapeJson(username)).append("\"");
        sb.append(",\"password\":\"").append(escapeJson(password)).append("\"");
        if (otp != null) {
            sb.append(",\"otp\":\"").append(escapeJson(otp)).append("\"");
        }
        sb.append("}");
        MvcResult res = mockMvc.perform(post(endpoint)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(sb.toString()))
                .andReturn();
        return JSON.readTree(res.getResponse().getContentAsString());
    }

    private boolean postMfaPreAuth(String username, int otp) throws Exception {
        String body = "{\"username\":\"" + escapeJson(username) + "\",\"otp\":" + otp + "}";
        String resp = mockMvc.perform(post("/v1/api/mfa/preauth")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString().trim();
        return "true".equals(resp);
    }

    private boolean postValidateOtp(String username, String otp) throws Exception {
        String body = "{\"username\":\"" + escapeJson(username) + "\",\"otp\":\"" + escapeJson(otp) + "\"}";
        MvcResult res = mockMvc.perform(post("/v1/api/otp/validate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andReturn();
        if (res.getResponse().getStatus() != 200) {
            return false;
        }
        return JSON.readTree(res.getResponse().getContentAsString()).path("valid").asBoolean();
    }

    private RadiusPacket sendRadius(String userName, String password, byte[] state) throws Exception {
        RadiusPacket packet = trySendRadius(RADIUS_SECRET, userName, password, state, 3000);
        assertNotNull(packet, "Expected RADIUS response for " + userName);
        return packet;
    }

    private RadiusPacket trySendRadius(String sharedSecret, String userName, String password, byte[] state, int timeoutMs) throws Exception {
        byte[] secretBytes = sharedSecret.getBytes(StandardCharsets.UTF_8);
        byte[] authenticator = new byte[16];
        RANDOM.nextBytes(authenticator);
        List<RadiusAttribute> attributes = new ArrayList<>();
        attributes.add(RadiusAttribute.ofString(RadiusConstants.ATTR_USER_NAME, userName));
        if (password != null) {
            attributes.add(new RadiusAttribute(RadiusConstants.ATTR_USER_PASSWORD,
                    RadiusCrypto.encryptUserPassword(password.getBytes(StandardCharsets.UTF_8), secretBytes, authenticator)));
        }
        if (state != null) {
            attributes.add(new RadiusAttribute(RadiusConstants.ATTR_STATE, state));
        }
        int id = radiusIdSeq.getAndIncrement() & 0xFF;
        byte[] packetBytes = RadiusCrypto.buildRequest(
                RadiusConstants.ACCESS_REQUEST, id, authenticator, attributes, secretBytes, true);
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(timeoutMs);
            socket.send(new DatagramPacket(packetBytes, packetBytes.length,
                    InetAddress.getByName("127.0.0.1"), radiusServer.getLocalPort()));
            byte[] buf = new byte[RadiusConstants.MAX_PACKET_LENGTH];
            DatagramPacket in = new DatagramPacket(buf, buf.length);
            socket.receive(in);
            return RadiusPacket.decode(in.getData(), in.getLength());
        } catch (SocketTimeoutException e) {
            return null;
        }
    }

    private byte[] obtainChallengeState(String userName, String password) throws Exception {
        RadiusPacket challenge = sendRadius(userName, password, null);
        assertEquals(RadiusConstants.ACCESS_CHALLENGE, challenge.getCode());
        return challenge.getAttribute(RadiusConstants.ATTR_STATE).orElseThrow().getValue();
    }

    private static String escapeJson(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    @Test
    void bootstrapAdminRequires2faAndWebTwoStepEnrollmentAndLoginEnforceCsrf() throws Exception {
        Admin seeded = adminRepository.findByUsername("admin").orElseThrow();
        assertTrue(seeded.getPassword().startsWith("$2"));
        assertNull(seeded.getOtpToken());
        assertNotNull(seeded.getPerson());

        // Anonymous browser access redirects to /login
        mockMvc.perform(get("/users"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("**/login"));

        // Browser POST /login without CSRF is rejected
        mockMvc.perform(post("/login")
                        .param("username", "admin")
                        .param("password", "admin-change-me"))
                .andExpect(status().isForbidden());

        // Wrong primary password fails
        MockHttpSession badSession = new MockHttpSession();
        mockMvc.perform(post("/login").with(csrf()).session(badSession)
                        .param("username", "admin")
                        .param("password", "wrong-pass"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login?error"));
        mockMvc.perform(get("/users").session(badSession))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("**/login"));

        // Valid primary password starts pre-2FA enrollment session WITHOUT authenticating /users yet
        MockHttpSession session = new MockHttpSession();
        mockMvc.perform(post("/login").with(csrf()).session(session)
                        .param("username", "admin")
                        .param("password", "admin-change-me"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login/enroll"));

        mockMvc.perform(get("/users").session(session))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("**/login"));

        MvcResult enrollPage = mockMvc.perform(get("/login/enroll").session(session))
                .andExpect(status().isOk())
                .andExpect(view().name("admin-enroll"))
                .andReturn();
        String pendingSecret = (String) enrollPage.getModelAndView().getModel().get("secret");
        assertNotNull(pendingSecret);
        assertEquals(0, otpTokenRepository.count(), "Enrollment secret must not be persisted until confirmed");

        long step = stableCurrentStep();
        // Wrong confirmation OTP does not enroll or authenticate
        mockMvc.perform(post("/login/enroll").with(csrf()).session(session)
                        .param("otp", wrongOtpForStep(pendingSecret, step)))
                .andExpect(status().isOk())
                .andExpect(view().name("admin-enroll"))
                .andExpect(model().attributeExists("error"));
        assertEquals(0, otpTokenRepository.count());

        // Confirm enrollment with valid OTP step (step - 1) -> persists OtpToken and opens /users
        String enrollOtp = otpForStep(pendingSecret, step - 1);
        mockMvc.perform(post("/login/enroll").with(csrf()).session(session)
                        .param("otp", enrollOtp))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/users"));

        assertEquals(1, otpTokenRepository.count());
        mockMvc.perform(get("/users").session(session))
                .andExpect(status().isOk())
                .andExpect(view().name("users"));

        // Sign out invalidates session
        mockMvc.perform(post("/logout").with(csrf()).session(session))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login?logout"));
        mockMvc.perform(get("/users").session(session))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("**/login"));

        // Second login goes to /login/otp, blocks replay of step-1, and accepts step
        MockHttpSession session2 = new MockHttpSession();
        mockMvc.perform(post("/login").with(csrf()).session(session2)
                        .param("username", "admin")
                        .param("password", "admin-change-me"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login/otp"));

        mockMvc.perform(post("/login/otp").with(csrf()).session(session2)
                        .param("otp", enrollOtp))
                .andExpect(status().isOk())
                .andExpect(view().name("admin-otp"))
                .andExpect(model().attributeExists("error"));

        mockMvc.perform(post("/login/otp").with(csrf()).session(session2)
                        .param("otp", otpForStep(pendingSecret, step)))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/users"));
        mockMvc.perform(get("/users").session(session2))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser
    void personSharedOtpTokenAuthenticatesUserAndAdminBlocksCrossPrivilegeReplayAndEnforcesSeparatePrimaryCredentials() throws Exception {
        long step = stableCurrentStep();
        String sharedSecret = distinctSecret(step);
        String secondSecret = distinctSecret(step);

        // Create two Persons and tokens via REST
        MvcResult alicePersonRes = mockMvc.perform(post("/v1/api/persons/create")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"displayName\":\"Alice Example\",\"email\":\"alice@example.com\"}"))
                .andExpect(status().isOk())
                .andReturn();
        long alicePersonId = JSON.readTree(alicePersonRes.getResponse().getContentAsString()).path("id").asLong();

        MvcResult bobPersonRes = mockMvc.perform(post("/v1/api/persons/create")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"displayName\":\"Bob Other\"}"))
                .andExpect(status().isOk())
                .andReturn();
        long bobPersonId = JSON.readTree(bobPersonRes.getResponse().getContentAsString()).path("id").asLong();

        MvcResult token1Res = mockMvc.perform(post("/v1/api/persons/" + alicePersonId + "/tokens")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"label\":\"yubikey-1\",\"secret\":\"" + sharedSecret + "\"}"))
                .andExpect(status().isOk())
                .andReturn();
        long token1Id = JSON.readTree(token1Res.getResponse().getContentAsString()).path("id").asLong();

        MvcResult bobTokenRes = mockMvc.perform(post("/v1/api/persons/" + bobPersonId + "/tokens")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"label\":\"bob-token\",\"secret\":\"" + secondSecret + "\"}"))
                .andExpect(status().isOk())
                .andReturn();
        long bobTokenId = JSON.readTree(bobTokenRes.getResponse().getContentAsString()).path("id").asLong();

        // Create User("alice") linked to Person(Alice) + OtpToken #1
        MvcResult createUserRes = mockMvc.perform(post("/v1/api/users/create")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice\",\"password\":\"" + USER_PASS
                                + "\",\"personId\":" + alicePersonId + ",\"otpTokenId\":" + token1Id + "}"))
                .andExpect(status().isOk())
                .andReturn();
        long aliceUserId = JSON.readTree(createUserRes.getResponse().getContentAsString()).path("id").asLong();
        assertTrue(aliceUserId > 0);

        // Enforce separate primary credentials & person ownership on Admin creation
        mockMvc.perform(post("/v1/api/admins/create")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice\",\"password\":\"" + ADMIN_PASS
                                + "\",\"personId\":" + alicePersonId + ",\"otpTokenId\":" + token1Id + "}"))
                .andExpect(status().isBadRequest());

        mockMvc.perform(post("/v1/api/admins/create")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice.admin\",\"password\":\"" + USER_PASS
                                + "\",\"personId\":" + alicePersonId + ",\"otpTokenId\":" + token1Id + "}"))
                .andExpect(status().isBadRequest());

        mockMvc.perform(post("/v1/api/admins/create")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice.admin\",\"password\":\"" + ADMIN_PASS
                                + "\",\"personId\":" + alicePersonId + ",\"otpTokenId\":" + bobTokenId + "}"))
                .andExpect(status().isBadRequest());

        // Valid Admin("alice.admin") linked to the same Person + shared OtpToken #1
        mockMvc.perform(post("/v1/api/admins/create")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice.admin\",\"password\":\"" + ADMIN_PASS
                                + "\",\"personId\":" + alicePersonId + ",\"otpTokenId\":" + token1Id + "}"))
                .andExpect(status().isOk());

        // Cross-privilege OTP replay check using shared OtpToken #1:
        String otpMinus1 = otpForStep(sharedSecret, step - 1);
        String otpCurrent = otpForStep(sharedSecret, step);
        String otpPlus1 = otpForStep(sharedSecret, step + 1);

        // 1. User consumes step-1 -> Admin MUST NOT replay step-1
        assertTrue(postLogin("/v1/api/auth/login", "alice", USER_PASS, otpMinus1).path("authenticated").asBoolean());
        JsonNode adminReplay = postLogin("/v1/api/admin/auth/login", "alice.admin", ADMIN_PASS, otpMinus1);
        assertFalse(adminReplay.path("authenticated").asBoolean());
        assertEquals("INVALID_OTP", adminReplay.path("status").asText());

        // 2. Admin consumes step -> User MUST NOT replay step (REST or RADIUS)
        assertTrue(postLogin("/v1/api/admin/auth/login", "alice.admin", ADMIN_PASS, otpCurrent).path("authenticated").asBoolean());
        assertFalse(postLogin("/v1/api/auth/login", "alice", USER_PASS, otpCurrent).path("authenticated").asBoolean());
        byte[] state = obtainChallengeState("alice", USER_PASS);
        assertEquals(RadiusConstants.ACCESS_REJECT, sendRadius("alice", otpCurrent, state).getCode());

        // 3. User advances to step+1 on RADIUS
        byte[] state2 = obtainChallengeState("alice", USER_PASS);
        assertEquals(RadiusConstants.ACCESS_ACCEPT, sendRadius("alice", otpPlus1, state2).getCode());

        // 4. Separate second OtpToken under same Person("Alice") works independently without touching OtpToken #1
        MvcResult token2Res = mockMvc.perform(post("/v1/api/persons/" + alicePersonId + "/tokens")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"label\":\"phone-alt\",\"secret\":\"" + secondSecret + "\"}"))
                .andExpect(status().isOk())
                .andReturn();
        long token2Id = JSON.readTree(token2Res.getResponse().getContentAsString()).path("id").asLong();

        mockMvc.perform(post("/v1/api/users/create")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice.alt\",\"password\":\"" + USER_PASS
                                + "\",\"personId\":" + alicePersonId + ",\"otpTokenId\":" + token2Id + "}"))
                .andExpect(status().isOk());

        assertTrue(postLogin("/v1/api/auth/login", "alice.alt", USER_PASS, otpForStep(secondSecret, step - 1))
                .path("authenticated").asBoolean());
        // Rotating second token leaves token1 intact
        mockMvc.perform(post("/v1/api/persons/tokens/" + token2Id + "/rotate"))
                .andExpect(status().isOk());
        assertNotEquals(sharedSecret, otpTokenRepository.findById(token2Id).orElseThrow().getSecret());
        assertEquals(sharedSecret, otpTokenRepository.findById(token1Id).orElseThrow().getSecret());
    }

    @Test
    void factorAwareLockoutIsolatesUserPasswordAttacksFromAdminWhileLockingBothOnTokenOrAdminBruteForce() throws Exception {
        long step = stableCurrentStep();
        String secret = distinctSecret(step);
        Person person = personService.createPerson(Person.builder().displayName("Alice Factor").build());
        OtpToken token = personService.createToken(person.getId(), "shared", secret);

        User aliceUser = userRepository.save(User.builder()
                .username("alice")
                .password(USER_PASS)
                .secret(secret)
                .person(person)
                .otpToken(token)
                .build());
        Admin aliceAdmin = adminRepository.save(Admin.builder()
                .username("alice.admin")
                .password(ADMIN_PASS)
                .person(person)
                .otpToken(token)
                .build());

        // Part A: 1st-factor / unauthenticated failures lock User("alice") ONLY; Admin("alice.admin") remains accessible
        assertFalse(postLogin("/v1/api/auth/login", "alice", "BadPassword!", null).path("authenticated").asBoolean());
        assertEquals(RadiusConstants.ACCESS_REJECT, sendRadius("alice", null, null).getCode());
        assertFalse(postValidateOtp(aliceUser.getUsername(), wrongOtpForStep(secret, step)));

        assertTrue(lockoutService.isLocked(aliceUser.getId()));
        assertFalse(lockoutService.isTokenLocked(token.getId()));
        assertFalse(lockoutService.isAdminLocked(aliceAdmin.getId()));
        assertFalse(postLogin("/v1/api/auth/login", "alice", USER_PASS, otpForStep(secret, step - 1))
                .path("authenticated").asBoolean());
        assertTrue(postLogin("/v1/api/admin/auth/login", "alice.admin", ADMIN_PASS, otpForStep(secret, step - 1))
                .path("authenticated").asBoolean(),
                "1st-factor User lockout must not DoS-lock linked Admin account");

        // Unlock User for Part B
        lockoutService.recordSuccess(aliceUser.getId());

        // Part B: 2nd-factor OTP brute force AFTER valid primary password locks the shared OtpToken (blocks both)
        String wrongOtp = wrongOtpForStep(secret, step);
        assertFalse(postLogin("/v1/api/auth/login", "alice", USER_PASS, wrongOtp).path("authenticated").asBoolean());
        assertFalse(postLogin("/v1/api/auth/login", "alice", USER_PASS, wrongOtp).path("authenticated").asBoolean());
        byte[] state = obtainChallengeState("alice", USER_PASS);
        assertEquals(RadiusConstants.ACCESS_REJECT, sendRadius("alice", wrongOtp, state).getCode());

        assertTrue(lockoutService.isTokenLocked(token.getId()));
        assertFalse(postLogin("/v1/api/auth/login", "alice", USER_PASS, otpForStep(secret, step))
                .path("authenticated").asBoolean());
        assertFalse(postLogin("/v1/api/admin/auth/login", "alice.admin", ADMIN_PASS, otpForStep(secret, step))
                .path("authenticated").asBoolean(),
                "Post-password OTP brute-force must lock shared OtpToken and block linked Admin");

        // Part C: Admin failures lock both Admin and the shared OtpToken (blocking User across Web and RADIUS)
        Person carolPerson = personService.createPerson(Person.builder().displayName("Carol").build());
        String carolSecret = distinctSecret(step);
        OtpToken carolToken = personService.createToken(carolPerson.getId(), "carol-tok", carolSecret);
        userRepository.save(User.builder()
                .username("carol")
                .password(USER_PASS)
                .secret(carolSecret)
                .person(carolPerson)
                .otpToken(carolToken)
                .build());
        Admin carolAdmin = adminRepository.save(Admin.builder()
                .username("carol.admin")
                .password(ADMIN_PASS)
                .person(carolPerson)
                .otpToken(carolToken)
                .build());

        for (int i = 0; i < 3; i++) {
            assertFalse(postLogin("/v1/api/admin/auth/login", "carol.admin", "WrongAdminPass!", null)
                    .path("authenticated").asBoolean());
        }
        assertTrue(lockoutService.isAdminLocked(carolAdmin.getId()));
        assertTrue(lockoutService.isTokenLocked(carolToken.getId()));
        assertFalse(postLogin("/v1/api/admin/auth/login", "carol.admin", ADMIN_PASS, otpForStep(carolSecret, step))
                .path("authenticated").asBoolean());
        assertFalse(postLogin("/v1/api/auth/login", "carol", USER_PASS, otpForStep(carolSecret, step))
                .path("authenticated").asBoolean());
        assertEquals(RadiusConstants.ACCESS_REJECT, sendRadius("carol", USER_PASS, null).getCode());
    }

    @Test
    @WithMockUser
    void personKillSwitchAndAccountLifecyclePreserveSharedToken() throws Exception {
        long step = stableCurrentStep();
        String secret = distinctSecret(step);
        Person person = personService.createPerson(Person.builder().displayName("Kill Switch").build());
        OtpToken token = personService.createToken(person.getId(), "tok", secret);
        User user = userRepository.save(User.builder()
                .username("ksuser").password(USER_PASS).secret(secret).person(person).otpToken(token).build());
        adminRepository.save(Admin.builder()
                .username("ksadmin").password(ADMIN_PASS).person(person).otpToken(token).build());

        // Issue active MFA approval + RADIUS challenge before disabling Person
        assertTrue(postMfaPreAuth("ksuser", Integer.parseInt(otpForStep(secret, step - 1))));
        byte[] state = obtainChallengeState("ksuser", USER_PASS);

        mockMvc.perform(put("/v1/api/persons/" + person.getId())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"displayName\":\"Kill Switch\",\"enabled\":false}"))
                .andExpect(status().isOk());

        assertEquals(RadiusConstants.ACCESS_REJECT, sendRadius("ksuser", null, null).getCode());
        assertEquals(RadiusConstants.ACCESS_REJECT, sendRadius("ksuser", otpForStep(secret, step), state).getCode());
        assertFalse(postLogin("/v1/api/auth/login", "ksuser", USER_PASS, otpForStep(secret, step)).path("authenticated").asBoolean());
        assertFalse(postValidateOtp(user.getUsername(), otpForStep(secret, step)));
        assertFalse(postLogin("/v1/api/admin/auth/login", "ksadmin", ADMIN_PASS, otpForStep(secret, step)).path("authenticated").asBoolean());

        // Re-enable Person restores Admin, and deleting User keeps Person + shared OtpToken alive for Admin
        mockMvc.perform(put("/v1/api/persons/" + person.getId())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"displayName\":\"Kill Switch\",\"enabled\":true}"))
                .andExpect(status().isOk());

        mockMvc.perform(delete("/v1/api/users/" + user.getId()))
                .andExpect(status().isOk());

        assertTrue(personRepository.findById(person.getId()).isPresent());
        assertTrue(otpTokenRepository.findById(token.getId()).isPresent());
        assertTrue(postLogin("/v1/api/admin/auth/login", "ksadmin", ADMIN_PASS, otpForStep(secret, step))
                .path("authenticated").asBoolean(),
                "Deleting User must preserve Person and shared OtpToken for remaining Admin");
    }

    @Test
    void adminLdapAuthenticationAndJitProvisioningIsolatedFromUserLdap() throws Exception {
        long step = stableCurrentStep();
        String aliceSecret = distinctSecret(step);
        Person alicePerson = personService.createPerson(Person.builder().displayName("Alice Corp").build());
        OtpToken aliceToken = personService.createToken(alicePerson.getId(), "alice-tok", aliceSecret);
        userRepository.save(User.builder()
                .username("alice").password(USER_PASS).secret(aliceSecret).person(alicePerson).otpToken(aliceToken).build());
        adminRepository.save(Admin.builder()
                .username("alice.admin").person(alicePerson).otpToken(aliceToken).build());

        try (MockLdapServer userLdap = new MockLdapServer("bob", "BobLdap!1");
             MockLdapServer adminLdap = new MockLdapServer("corpadmin", "CorpAdmin!2", "alice.admin", "AliceAdminLdap!3")) {
            ldapDirectoryRepository.saveAndFlush(LdapDirectory.builder()
                    .name("user-corp")
                    .priority(10)
                    .enabled(true)
                    .userEnabled(true)
                    .adminEnabled(false)
                    .url("ldap://127.0.0.1:" + userLdap.getPort())
                    .baseDn("dc=corp,dc=org")
                    .userSearchFilter("(&(objectClass=person)(|(uid={0})(sAMAccountName={0})))")
                    .bindDn("cn=admin,dc=corp,dc=org")
                    .bindPassword("secret")
                    .autoProvision(true)
                    .fallbackToLocal(true)
                    .usernameAttributes("uid,sAMAccountName")
                    .build());

            ldapDirectoryRepository.saveAndFlush(LdapDirectory.builder()
                    .name("admin-corp")
                    .priority(20)
                    .enabled(true)
                    .userEnabled(false)
                    .adminEnabled(true)
                    .url("ldap://127.0.0.1:" + adminLdap.getPort())
                    .baseDn("dc=corp,dc=org")
                    .userSearchFilter("(&(objectClass=person)(|(uid={0})(sAMAccountName={0})))")
                    .bindDn("cn=admin,dc=corp,dc=org")
                    .bindPassword("secret")
                    .autoProvision(true)
                    .fallbackToLocal(true)
                    .usernameAttributes("uid,sAMAccountName")
                    .build());

            // 1. User-LDAP account "bob" CANNOT authenticate or JIT-provision as an Admin
            JsonNode bobOnAdmin = postLogin("/v1/api/admin/auth/login", "bob", "BobLdap!1", null);
            assertFalse(bobOnAdmin.path("authenticated").asBoolean());
            assertTrue(adminRepository.findByUsername("bob").isEmpty());
            assertEquals("ENROLLMENT_REQUIRED",
                    postLogin("/v1/api/auth/login", "bob", "BobLdap!1", null).path("status").asText());

            // 2. Admin-LDAP account "corpadmin" CANNOT log in as a User, and JIT-provisions as Admin
            assertFalse(postLogin("/v1/api/auth/login", "corpadmin", "CorpAdmin!2", null).path("authenticated").asBoolean());
            assertTrue(userRepository.findByUsername("corpadmin").isEmpty());

            JsonNode corpEnroll = postLogin("/v1/api/admin/auth/login", "corpadmin", "CorpAdmin!2", null);
            assertEquals("ENROLLMENT_REQUIRED", corpEnroll.path("status").asText());
            assertEquals("LDAP", corpEnroll.path("authenticationSource").asText());
            String corpSecret = corpEnroll.path("secret").asText();
            assertFalse(corpSecret.isBlank());
            Admin provisioned = adminRepository.findByUsername("corpadmin").orElseThrow();
            assertNull(provisioned.getPassword(), "LDAP JIT admin should not store an LDAP password locally");

            JsonNode corpAuth = postLogin("/v1/api/admin/auth/login", "corpadmin", "CorpAdmin!2",
                    otpForStep(corpSecret, step - 1));
            assertTrue(corpAuth.path("authenticated").asBoolean());
            assertEquals("LDAP", corpAuth.path("authenticationSource").asText());

            // 3. Linked Admin("alice.admin") authenticates via LDAP password + shared Person OtpToken with cross-privilege replay blocked
            assertTrue(postLogin("/v1/api/admin/auth/login", "alice.admin", "AliceAdminLdap!3",
                    otpForStep(aliceSecret, step - 1)).path("authenticated").asBoolean());
            assertFalse(postLogin("/v1/api/auth/login", "alice", USER_PASS,
                    otpForStep(aliceSecret, step - 1)).path("authenticated").asBoolean(),
                    "User must not replay OTP consumed by LDAP-authenticated Admin");
            assertTrue(postLogin("/v1/api/auth/login", "alice", USER_PASS,
                    otpForStep(aliceSecret, step)).path("authenticated").asBoolean());

            // 4. Local break-glass admin still works via fallbackToLocal=true
            JsonNode localFallbackEnroll = postLogin("/v1/api/admin/auth/login", "admin", "admin-change-me", null);
            assertEquals("ENROLLMENT_REQUIRED", localFallbackEnroll.path("status").asText());
            assertEquals("LOCAL", localFallbackEnroll.path("authenticationSource").asText());
        }
    }

    @Test
    @WithMockUser
    void runtimeConfigurationAndSecretsAreReadFromDatabaseAndEditableViaApi() throws Exception {
        long step = stableCurrentStep();
        String secret = distinctSecret(step);
        mockMvc.perform(post("/v1/api/users/create")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"dbuser\",\"password\":\"" + USER_PASS + "\",\"secret\":\"" + secret + "\"}"))
                .andExpect(status().isOk());
        assertTrue(postMfaPreAuth("dbuser", Integer.parseInt(otpForStep(secret, step - 1))));

        // 1. Update SecurityPolicy dynamically via DB API -> immediately applied on RADIUS without restart
        mockMvc.perform(put("/v1/api/policies/current")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"maxFailures\":5,\"lockoutSeconds\":120,\"failureWindowSeconds\":300,"
                                + "\"challengeTtlSeconds\":60,\"challengeMaxPending\":10000,"
                                + "\"mfaApprovalTtlSeconds\":60,\"mfaMaxFailedAttempts\":5,"
                                + "\"mfaLockoutWindowSeconds\":300,\"otpReuseWindowSeconds\":120,"
                                + "\"requireMessageAuthenticator\":true,\"stripRealm\":false,"
                                + "\"challengePrompt\":\"Custom DB Prompt\",\"mfaOutOfBandEnabled\":false}"))
                .andExpect(status().isOk());

        assertEquals(RadiusConstants.ACCESS_REJECT,
                sendRadius("CORP\\dbuser", USER_PASS, null).getCode(),
                "DB policy stripRealm=false must take effect immediately");
        RadiusPacket challenge = sendRadius("dbuser", USER_PASS, null);
        assertEquals(RadiusConstants.ACCESS_CHALLENGE, challenge.getCode());
        assertEquals("Custom DB Prompt",
                challenge.getAttribute(RadiusConstants.ATTR_REPLY_MESSAGE).orElseThrow().getValueAsString());
        assertEquals(RadiusConstants.ACCESS_REJECT,
                sendRadius("dbuser", null, null).getCode(),
                "DB policy mfaOutOfBandEnabled=false must take effect immediately");

        // Restore OOB + stripRealm in DB policy -> works immediately
        mockMvc.perform(put("/v1/api/policies/current")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"maxFailures\":5,\"lockoutSeconds\":120,\"failureWindowSeconds\":300,"
                                + "\"challengeTtlSeconds\":60,\"challengeMaxPending\":10000,"
                                + "\"mfaApprovalTtlSeconds\":60,\"mfaMaxFailedAttempts\":5,"
                                + "\"mfaLockoutWindowSeconds\":300,\"otpReuseWindowSeconds\":120,"
                                + "\"requireMessageAuthenticator\":false,\"stripRealm\":true,"
                                + "\"challengePrompt\":\"Enter your one-time passcode\",\"mfaOutOfBandEnabled\":true}"))
                .andExpect(status().isOk());
        assertEquals(RadiusConstants.ACCESS_ACCEPT, sendRadius("CORP\\dbuser", null, null).getCode());

        // 2. Manage RadiusClient shared secrets dynamically in DB
        MvcResult clientRes = mockMvc.perform(post("/v1/api/radius-clients/create")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"loopback-db\",\"address\":\"127.0.0.1/32\","
                                + "\"sharedSecret\":\"db-client-secret-1\",\"active\":true}"))
                .andExpect(status().isOk())
                .andReturn();
        long clientId = JSON.readTree(clientRes.getResponse().getContentAsString()).path("id").asLong();

        assertNull(trySendRadius(RADIUS_SECRET, "dbuser", USER_PASS, null, 350),
                "Legacy secret must be dropped once more-specific DB client matches 127.0.0.1/32");
        assertEquals(RadiusConstants.ACCESS_CHALLENGE,
                trySendRadius("db-client-secret-1", "dbuser", USER_PASS, null, 3000).getCode());

        mockMvc.perform(put("/v1/api/radius-clients/" + clientId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"loopback-db\",\"address\":\"127.0.0.1/32\","
                                + "\"sharedSecret\":\"db-client-secret-2\",\"active\":true}"))
                .andExpect(status().isOk());
        assertEquals(RadiusConstants.ACCESS_CHALLENGE,
                trySendRadius("db-client-secret-2", "dbuser", USER_PASS, null, 3000).getCode());

        // 3. Create an Admin LDAP directory purely via DB API
        try (MockLdapServer adminLdap = new MockLdapServer("dbldapadmin", "DbLdap!9")) {
            mockMvc.perform(post("/v1/api/ldap-directories/create")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"name\":\"db-admin-ldap\",\"enabled\":true,\"userEnabled\":false,\"adminEnabled\":true,"
                                    + "\"priority\":5,\"url\":\"ldap://127.0.0.1:" + adminLdap.getPort() + "\","
                                    + "\"baseDn\":\"dc=corp,dc=org\","
                                    + "\"userSearchFilter\":\"(&(objectClass=person)(|(uid={0})(sAMAccountName={0})))\","
                                    + "\"bindDn\":\"cn=admin,dc=corp,dc=org\",\"bindPassword\":\"secret\","
                                    + "\"autoProvision\":true,\"fallbackToLocal\":false}"))
                    .andExpect(status().isOk());

            JsonNode enrolled = postLogin("/v1/api/admin/auth/login", "dbldapadmin", "DbLdap!9", null);
            assertEquals("ENROLLMENT_REQUIRED", enrolled.path("status").asText());
            assertEquals("LDAP", enrolled.path("authenticationSource").asText());
        }
    }

    static class MockLdapServer implements AutoCloseable {
        private final ServerSocket serverSocket;
        private final Thread thread;
        private volatile boolean running = true;
        private final List<String[]> entries = new ArrayList<>();

        MockLdapServer(String... userPasswordPairs) throws IOException {
            for (int i = 0; i + 1 < userPasswordPairs.length; i += 2) {
                entries.add(new String[]{userPasswordPairs[i], userPasswordPairs[i + 1]});
            }
            this.serverSocket = new ServerSocket(0);
            this.thread = new Thread(this::run);
            this.thread.setDaemon(true);
            this.thread.start();
        }

        int getPort() {
            return serverSocket.getLocalPort();
        }

        private void run() {
            while (running) {
                try {
                    Socket socket = serverSocket.accept();
                    Thread worker = new Thread(() -> handleClient(socket));
                    worker.setDaemon(true);
                    worker.start();
                } catch (IOException e) {
                    break;
                }
            }
        }

        private void handleClient(Socket socket) {
            try (socket;
                 InputStream in = socket.getInputStream();
                 OutputStream out = socket.getOutputStream()) {
                while (running) {
                    int tag = in.read();
                    if (tag == -1) break;
                    if (tag != 0x30) continue;
                    byte[] seqBytes = readBytes(in, readLength(in));
                    ByteArrayInputStream bin = new ByteArrayInputStream(seqBytes);

                    bin.read();
                    byte[] idBytes = readBytes(bin, readLength(bin));
                    int messageId = 0;
                    for (byte b : idBytes) {
                        messageId = (messageId << 8) | (b & 0xFF);
                    }

                    int opTag = bin.read();
                    byte[] opBytes = readBytes(bin, readLength(bin));
                    ByteArrayInputStream opIn = new ByteArrayInputStream(opBytes);

                    if (opTag == 0x60) {
                        opIn.read();
                        readBytes(opIn, readLength(opIn));
                        opIn.read();
                        String bindDn = new String(readBytes(opIn, readLength(opIn)), StandardCharsets.UTF_8);
                        opIn.read();
                        String pass = new String(readBytes(opIn, readLength(opIn)), StandardCharsets.UTF_8);
                        boolean ok = (bindDn.isEmpty() && pass.isEmpty())
                                || ("cn=admin,dc=corp,dc=org".equals(bindDn) && "secret".equals(pass))
                                || entries.stream().anyMatch(e ->
                                ("uid=" + e[0] + ",ou=users,dc=corp,dc=org").equalsIgnoreCase(bindDn) && e[1].equals(pass));
                        sendBindResponse(out, messageId, ok ? 0 : 49);
                    } else if (opTag == 0x63) {
                        opIn.read();
                        readBytes(opIn, readLength(opIn));
                        for (int i = 0; i < 5; i++) {
                            opIn.read();
                            readBytes(opIn, readLength(opIn));
                        }
                        String filterStr = new String(readRemaining(opIn), StandardCharsets.UTF_8).toLowerCase(Locale.ROOT);
                        for (String[] e : entries) {
                            String candidate = e[0].toLowerCase(Locale.ROOT);
                            String berToken = ((char) candidate.getBytes(StandardCharsets.UTF_8).length) + candidate;
                            if (filterStr.contains(berToken)) {
                                sendSearchResultEntry(out, messageId, "uid=" + e[0] + ",ou=users,dc=corp,dc=org", e[0]);
                                break;
                            }
                        }
                        sendSearchResultDone(out, messageId, 0);
                    } else if (opTag == 0x42) {
                        break;
                    }
                }
            } catch (IOException ignored) {
            }
        }

        private void sendBindResponse(OutputStream out, int messageId, int resultCode) throws IOException {
            ByteArrayOutputStream res = new ByteArrayOutputStream();
            res.write(0x0A); res.write(1); res.write(resultCode);
            res.write(0x04); res.write(0);
            res.write(0x04); res.write(0);
            sendLdapMessage(out, messageId, 0x61, res.toByteArray());
        }

        private void sendSearchResultEntry(OutputStream out, int messageId, String dn, String uid) throws IOException {
            ByteArrayOutputStream res = new ByteArrayOutputStream();
            byte[] dnBytes = dn.getBytes(StandardCharsets.UTF_8);
            res.write(0x04);
            writeLength(res, dnBytes.length);
            res.write(dnBytes);
            ByteArrayOutputStream attrs = new ByteArrayOutputStream();
            writeAttribute(attrs, "uid", uid);
            byte[] attrBytes = attrs.toByteArray();
            res.write(0x30);
            writeLength(res, attrBytes.length);
            res.write(attrBytes);
            sendLdapMessage(out, messageId, 0x64, res.toByteArray());
        }

        private void writeAttribute(OutputStream out, String type, String value) throws IOException {
            ByteArrayOutputStream attr = new ByteArrayOutputStream();
            byte[] typeBytes = type.getBytes(StandardCharsets.UTF_8);
            attr.write(0x04);
            writeLength(attr, typeBytes.length);
            attr.write(typeBytes);
            ByteArrayOutputStream vals = new ByteArrayOutputStream();
            byte[] valBytes = value.getBytes(StandardCharsets.UTF_8);
            vals.write(0x04);
            writeLength(vals, valBytes.length);
            vals.write(valBytes);
            byte[] valsBytes = vals.toByteArray();
            attr.write(0x31);
            writeLength(attr, valsBytes.length);
            attr.write(valsBytes);
            byte[] attrBytes = attr.toByteArray();
            out.write(0x30);
            writeLength(out, attrBytes.length);
            out.write(attrBytes);
        }

        private void sendSearchResultDone(OutputStream out, int messageId, int resultCode) throws IOException {
            ByteArrayOutputStream res = new ByteArrayOutputStream();
            res.write(0x0A); res.write(1); res.write(resultCode);
            res.write(0x04); res.write(0);
            res.write(0x04); res.write(0);
            sendLdapMessage(out, messageId, 0x65, res.toByteArray());
        }

        private void sendLdapMessage(OutputStream out, int messageId, int protocolOpTag, byte[] body) throws IOException {
            ByteArrayOutputStream msg = new ByteArrayOutputStream();
            msg.write(0x02);
            msg.write(1);
            msg.write(messageId);
            msg.write(protocolOpTag);
            writeLength(msg, body.length);
            msg.write(body);
            byte[] msgBytes = msg.toByteArray();
            out.write(0x30);
            writeLength(out, msgBytes.length);
            out.write(msgBytes);
            out.flush();
        }

        private int readLength(InputStream in) throws IOException {
            int b = in.read();
            if (b == -1) throw new EOFException();
            if ((b & 0x80) == 0) return b;
            int numBytes = b & 0x7F;
            int len = 0;
            for (int i = 0; i < numBytes; i++) {
                int next = in.read();
                if (next == -1) throw new EOFException();
                len = (len << 8) | next;
            }
            return len;
        }

        private void writeLength(OutputStream out, int length) throws IOException {
            if (length < 128) {
                out.write(length);
            } else if (length < 256) {
                out.write(0x81);
                out.write(length);
            } else {
                out.write(0x82);
                out.write((length >> 8) & 0xFF);
                out.write(length & 0xFF);
            }
        }

        private byte[] readBytes(InputStream in, int length) throws IOException {
            byte[] bytes = new byte[length];
            int read = 0;
            while (read < length) {
                int r = in.read(bytes, read, length - read);
                if (r == -1) throw new EOFException();
                read += r;
            }
            return bytes;
        }

        private byte[] readRemaining(InputStream in) throws IOException {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buf = new byte[128];
            int r;
            while ((r = in.read(buf)) != -1) {
                baos.write(buf, 0, r);
            }
            return baos.toByteArray();
        }

        @Override
        public void close() {
            running = false;
            try {
                serverSocket.close();
            } catch (IOException ignored) {
            }
        }
    }
}
