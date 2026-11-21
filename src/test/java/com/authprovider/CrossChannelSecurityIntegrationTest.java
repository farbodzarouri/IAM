package com.authprovider;

import static com.authprovider.OAuthTestSupport.bearer;
import com.authprovider.dto.LoginRequest;
import com.authprovider.entity.LdapDirectory;
import com.authprovider.entity.SecurityPolicy;
import com.authprovider.entity.User;
import com.authprovider.radius.RadiusAttribute;
import com.authprovider.radius.RadiusAuthenticationHandler;
import com.authprovider.radius.RadiusClientRegistry;
import com.authprovider.radius.RadiusConstants;
import com.authprovider.radius.RadiusCrypto;
import com.authprovider.radius.RadiusPacket;
import com.authprovider.radius.RadiusServer;
import com.authprovider.repository.AuthFailureRecordRepository;
import com.authprovider.repository.LdapDirectoryRepository;
import com.authprovider.repository.MfaApprovalRepository;
import com.authprovider.repository.RadiusChallengeSessionRepository;
import com.authprovider.repository.SecurityPolicyRepository;
import com.authprovider.repository.UserRepository;
import com.authprovider.service.LoginService;
import com.authprovider.service.MfaPreAuthService;
import com.authprovider.service.OcraService;
import com.authprovider.service.SecretGenerator;
import com.authprovider.service.UserOtpService;
import com.authprovider.service.UserService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.binary.Base32;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.http.MediaType;
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
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

@SpringBootTest(properties = {
        "radius.port=0",
        "radius.bind-address=127.0.0.1",
        "iam.bootstrap.radius.shared-secret=cross-secret",
        "iam.bootstrap.policy.max-failures=3",
        "iam.bootstrap.policy.lockout-seconds=120",
        "iam.bootstrap.policy.mfa-approval-ttl-seconds=60",
        "iam.bootstrap.policy.challenge-ttl-seconds=60"
})
@AutoConfigureMockMvc
class CrossChannelSecurityIntegrationTest {

    private static final String RADIUS_SECRET = "cross-secret";
    private static final String PASSWORD = "Str0ng!Password";
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final ObjectMapper JSON = new ObjectMapper();

    @Autowired private MockMvc mockMvc;
    @Autowired private LoginService loginService;
    @Autowired private MfaPreAuthService mfaPreAuthService;
    private static final Base32 BASE32 = new Base32();

    @Autowired private UserService userService;
    @Autowired private UserOtpService userOtpService;
    @Autowired private OcraService ocraService;
    @Autowired private SecretGenerator secretGenerator;
    @Autowired private RadiusServer radiusServer;
    @Autowired private RadiusAuthenticationHandler radiusHandler;
    @Autowired private UserRepository userRepository;
    @Autowired private AuthFailureRecordRepository failureRepository;
    @Autowired private MfaApprovalRepository approvalRepository;
    @Autowired private RadiusChallengeSessionRepository challengeRepository;
    @Autowired private SecurityPolicyRepository policyRepository;
    @Autowired private LdapDirectoryRepository ldapDirectoryRepository;
    @Autowired private Clock clock;

    private final AtomicInteger radiusIdSeq = new AtomicInteger(1);

    @BeforeEach
    void setUp() {
        cleanState();
        configurePolicy(3, 3, 120, 300, 300);
    }

    @AfterEach
    void tearDown() {
        cleanState();
        configurePolicy(3, 3, 120, 300, 300);
    }

    private void cleanState() {
        for (User existing : userRepository.findAll()) {
            try {
                if (existing.getId() != null) {
                    userService.deleteUser(existing.getId());
                }
            } catch (Exception ignored) {
            }
        }
        challengeRepository.deleteAll();
        approvalRepository.deleteAll();
        failureRepository.deleteAll();
        resetDirectories();
        userRepository.deleteAll();
    }

    private void resetDirectories() {
        List<LdapDirectory> existing = ldapDirectoryRepository.findAll();
        for (LdapDirectory dir : existing) {
            if ("default".equals(dir.getName())) {
                dir.setEnabled(false);
                ldapDirectoryRepository.saveAndFlush(dir);
            } else {
                ldapDirectoryRepository.delete(dir);
            }
        }
        ldapDirectoryRepository.flush();
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
        policy.setOtpReuseWindowSeconds(120);
        policyRepository.saveAndFlush(policy);
    }

    private User createUser(String username, String password, String secret) {
        return userService.saveUser(User.builder()
                .username(username)
                .password(password)
                .secret(secret)
                .build());
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

    private String otpForStep(String secret, long step) {
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

    private String wrongOtpForStep(String secret, long step) {
        Set<String> validSet = Set.of(
                otpForStep(secret, step - 1),
                otpForStep(secret, step),
                otpForStep(secret, step + 1));
        int candidate = 100001;
        while (validSet.contains(String.format("%06d", candidate))) {
            candidate++;
        }
        return String.format("%06d", candidate);
    }

    private long stableCurrentStep() throws InterruptedException {
        while (true) {
            long nowMs = clock.millis();
            long offsetInBucket = nowMs % 30000L;
            if (offsetInBucket <= 23000L) {
                return nowMs / 30000L;
            }
            Thread.sleep(200);
        }
    }

    private RadiusPacket sendRadius(int port, String sharedSecret, String userName, String password, byte[] state) throws Exception {
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
            socket.setSoTimeout(3000);
            DatagramPacket out = new DatagramPacket(packetBytes, packetBytes.length,
                    InetAddress.getByName("127.0.0.1"), port);
            socket.send(out);
            byte[] buf = new byte[RadiusConstants.MAX_PACKET_LENGTH];
            DatagramPacket in = new DatagramPacket(buf, buf.length);
            socket.receive(in);
            return RadiusPacket.decode(in.getData(), in.getLength());
        } catch (IOException e) {
            throw new AssertionError("RADIUS request failed on port " + port, e);
        }
    }

    private RadiusPacket sendRadius(String userName, String password, byte[] state) throws Exception {
        return sendRadius(radiusServer.getLocalPort(), RADIUS_SECRET, userName, password, state);
    }

    private byte[] obtainChallengeState(int port, String sharedSecret, String userName, String password) throws Exception {
        RadiusPacket challenge = sendRadius(port, sharedSecret, userName, password, null);
        assertEquals(RadiusConstants.ACCESS_CHALLENGE, challenge.getCode(),
                "Expected ACCESS_CHALLENGE for " + userName + ", got code=" + challenge.getCode());
        return challenge.getAttribute(RadiusConstants.ATTR_STATE).orElseThrow().getValue();
    }

    private byte[] obtainChallengeState(String userName) throws Exception {
        return obtainChallengeState(radiusServer.getLocalPort(), RADIUS_SECRET, userName, PASSWORD);
    }

    private JsonNode postWebLogin(String username, String password, String otp) throws Exception {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"username\":\"").append(escapeJson(username)).append("\"");
        sb.append(",\"password\":\"").append(escapeJson(password)).append("\"");
        if (otp != null) {
            sb.append(",\"otp\":\"").append(escapeJson(otp)).append("\"");
        }
        sb.append("}");
        MvcResult res = mockMvc.perform(post("/v1/api/auth/login").with(bearer())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(sb.toString()))
                .andReturn();
        return JSON.readTree(res.getResponse().getContentAsString());
    }

    private boolean postMfaPreAuth(String username, int otp) throws Exception {
        String body = "{\"username\":\"" + escapeJson(username) + "\",\"otp\":" + otp + "}";
        MvcResult res = mockMvc.perform(post("/v1/api/mfa/preauth").with(bearer())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andReturn();
        int status = res.getResponse().getStatus();
        String content = res.getResponse().getContentAsString().trim();
        if (status == 200 && "true".equals(content)) {
            return true;
        }
        assertTrue(status >= 400 || "false".equals(content),
                "Unexpected /v1/api/mfa/preauth response: status=" + status + " body=" + content);
        return false;
    }

    private boolean postWebMfaForm(String username, String otp) throws Exception {
        MvcResult res = mockMvc.perform(post("/mfa")
                        .param("username", username)
                        .param("otp", otp))
                .andExpect(status().isOk())
                .andExpect(view().name("mfa"))
                .andReturn();
        var mav = res.getModelAndView();
        assertNotNull(mav, "Expected ModelAndView from POST /mfa");
        return Boolean.TRUE.equals(mav.getModel().get("success"));
    }

    private boolean postValidateOtp(String username, int otp) throws Exception {
        String body = "{\"username\":\"" + escapeJson(username) + "\",\"otp\":\"" + String.format("%06d", otp) + "\"}";
        MvcResult res = mockMvc.perform(post("/v1/api/otp/validate").with(bearer())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andReturn();
        int status = res.getResponse().getStatus();
        String content = res.getResponse().getContentAsString().trim();
        if (status == 200 && JSON.readTree(content).path("valid").asBoolean()) {
            return true;
        }
        assertTrue(status >= 400 || !JSON.readTree(content).path("valid").asBoolean(),
                "Unexpected /v1/api/otp/validate response: status=" + status + " body=" + content);
        return false;
    }

    private boolean postValidateOcra(String username, String challenge, String otp) throws Exception {
        String body = "{\"username\":\"" + escapeJson(username) + "\",\"challenge\":\"" + escapeJson(challenge)
                + "\",\"otp\":\"" + escapeJson(otp) + "\"}";
        MvcResult res = mockMvc.perform(post("/v1/api/otp/validate-ocra").with(bearer())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andReturn();
        int status = res.getResponse().getStatus();
        String content = res.getResponse().getContentAsString().trim();
        if (status == 200 && JSON.readTree(content).path("valid").asBoolean()) {
            return true;
        }
        assertTrue(status >= 400 || !JSON.readTree(content).path("valid").asBoolean(),
                "Unexpected /v1/api/otp/validate-ocra response: status=" + status + " body=" + content);
        return false;
    }

    private static String escapeJson(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    @Test
    @WithMockUser
    void canonicalIdentityAndDirectoryFallbackResolveSameAccountAcrossAllChannels() throws Exception {
        long step = stableCurrentStep();
        String localSecret = distinctSecret(step);
        User localUser = createUser("localonly", PASSWORD, localSecret);

        // Part A: Local-only mode (LDAP disabled) resolves qualified and case-variant usernames across all channels
        assertTrue(postWebLogin("CORP\\LoCaLoNlY", PASSWORD, otpForStep(localSecret, step - 1))
                .path("authenticated").asBoolean());
        assertEquals(localUser.getId(),
                postWebLogin("localonly@corp.local", PASSWORD, otpForStep(localSecret, step))
                        .path("userId").asLong());
        assertTrue(postMfaPreAuth("LOCALONLY", Integer.parseInt(otpForStep(localSecret, step + 1))));
        assertEquals(RadiusConstants.ACCESS_ACCEPT, sendRadius("CORP\\localonly", null, null).getCode());

        // Part B: With federated LDAP enabled (fallbackToLocal=true, autoProvision=true),
        // absent local accounts fall back cleanly across realm-qualified/case-variant names,
        // and LDAP accounts JIT-provision once and link to the exact same canonical account everywhere.
        long freshStep = stableCurrentStep();
        String fallbackSecret = distinctSecret(freshStep);
        User fallbackUser = createUser("fallbackuser", PASSWORD, fallbackSecret);
        long existingCount = userRepository.count();

        try (MockLdapServer ldap = new MockLdapServer("ldapuser", "LdapPass!123")) {
            ldapDirectoryRepository.saveAndFlush(LdapDirectory.builder()
                    .name("corp-ldap")
                    .realm("CORP,corp.local")
                    .priority(10)
                    .enabled(true)
                    .url("ldap://127.0.0.1:" + ldap.getPort())
                    .baseDn("dc=corp,dc=org")
                    .userSearchFilter("(&(objectClass=person)(|(uid={0})(sAMAccountName={0})))")
                    .bindDn("cn=admin,dc=corp,dc=org")
                    .bindPassword("secret")
                    .autoProvision(true)
                    .fallbackToLocal(true)
                    .usernameAttributes("uid,sAMAccountName")
                    .build());

            // Local fallback from Web Login and RADIUS using realm-qualified / mixed-case variants
            JsonNode fbLogin1 = postWebLogin("CORP\\FaLlBaCkUsEr", PASSWORD, otpForStep(fallbackSecret, freshStep - 1));
            assertTrue(fbLogin1.path("authenticated").asBoolean());
            assertEquals("LOCAL", fbLogin1.path("authenticationSource").asText());
            assertEquals(fallbackUser.getId(), fbLogin1.path("userId").asLong());

            byte[] fbState = obtainChallengeState(radiusServer.getLocalPort(), RADIUS_SECRET,
                    "fallbackuser@corp.local", PASSWORD);
            assertEquals(RadiusConstants.ACCESS_ACCEPT,
                    sendRadius("CORP\\FALLBACKUSER", otpForStep(fallbackSecret, freshStep), fbState).getCode());

            assertTrue(postMfaPreAuth("fallbackuser@corp.local", Integer.parseInt(otpForStep(fallbackSecret, freshStep + 1))));
            assertEquals(RadiusConstants.ACCESS_ACCEPT, sendRadius("FaLlBaCkUsEr", null, null).getCode());
            assertEquals(existingCount, userRepository.count(),
                    "Fallback authentication must not create duplicate local accounts");

            // LDAP account JIT-provisions once and resolves identically across all channels
            JsonNode enrollResp = postWebLogin("CORP\\LdApUsEr", "LdapPass!123", null);
            assertEquals("ENROLLMENT_REQUIRED", enrollResp.path("status").asText());
            assertEquals("LDAP", enrollResp.path("authenticationSource").asText());
            long ldapUserId = enrollResp.path("userId").asLong();
            assertTrue(ldapUserId > 0);
            String ldapSecret = enrollResp.path("secret").asText();
            assertFalse(ldapSecret.isBlank());
            assertEquals(existingCount + 1, userRepository.count(),
                    "JIT provisioning must create exactly one canonical local account");

            User savedLdap = userRepository.findById(ldapUserId).orElseThrow();
            assertEquals("ldapuser", savedLdap.getUsername().toLowerCase(Locale.ROOT));
            assertFalse(savedLdap.getUsername().contains("\\") || savedLdap.getUsername().contains("@"),
                    "Provisioned canonical username must not retain realm affixes");

            long ldapStep = stableCurrentStep();
            String[] threeCodes = ensureThreeDistinctSteps(ldapSecret, ldapStep);
            JsonNode dirWeb = postWebLogin("ldapuser@corp.local", "LdapPass!123", threeCodes[0]);
            assertTrue(dirWeb.path("authenticated").asBoolean());
            assertEquals("LDAP", dirWeb.path("authenticationSource").asText());
            assertEquals(ldapUserId, dirWeb.path("userId").asLong());

            byte[] dirState = obtainChallengeState(radiusServer.getLocalPort(), RADIUS_SECRET,
                    "CORP\\LDAPUSER", "LdapPass!123");
            assertEquals(RadiusConstants.ACCESS_ACCEPT,
                    sendRadius("ldapuser@corp.local", threeCodes[1], dirState).getCode());

            assertTrue(postMfaPreAuth("LDAPUSER", Integer.parseInt(threeCodes[2])));
            assertEquals(RadiusConstants.ACCESS_ACCEPT, sendRadius("CORP\\ldapuser", null, null).getCode());
            assertEquals(existingCount + 1, userRepository.count(),
                    "Cross-channel LDAP authentications must reuse the same single local account");

            // Rotate LDAP user's OTP secret before testing directory-backed lockout so unused fresh codes exist
            String rotatedLdapSecret = mockMvc.perform(post("/v1/api/otp/generate/" + savedLdap.getUsername()))
                    .andExpect(status().isOk())
                    .andReturn().getResponse().getContentAsString().trim();
            long postRotStep = stableCurrentStep();
            String[] postRotCodes = ensureThreeDistinctSteps(rotatedLdapSecret, postRotStep);
            String wrongLdapOtp = wrongOtpForStep(rotatedLdapSecret, postRotStep);

            // 3 cross-channel failures (including trying local PASSWORD while fallbackToLocal=true) lock canonical ldapuser
            assertFalse(postWebLogin("CORP\\ldapuser", PASSWORD, null).path("authenticated").asBoolean());
            assertEquals(RadiusConstants.ACCESS_REJECT,
                    sendRadius("ldapuser@corp.local", "WrongLdapPw!", null).getCode());
            assertFalse(postMfaPreAuth("LDAPUSER", Integer.parseInt(wrongLdapOtp)));

            assertFalse(postWebLogin("ldapuser", "LdapPass!123", postRotCodes[0]).path("authenticated").asBoolean(),
                    "Locked LDAP-backed account must be rejected on Web Login even with valid LDAP credentials and fresh OTP");
            assertFalse(postMfaPreAuth("CORP\\ldapuser", Integer.parseInt(postRotCodes[1])),
                    "Locked LDAP-backed account must be rejected on MFA Pre-Auth");
            assertFalse(postValidateOtp(savedLdap.getUsername(), Integer.parseInt(postRotCodes[2])),
                    "Locked LDAP-backed account must be rejected on /v1/api/otp/validate");
            assertEquals(RadiusConstants.ACCESS_REJECT,
                    sendRadius("ldapuser@corp.local", "LdapPass!123", null).getCode(),
                    "Locked LDAP-backed account must be rejected on In-Band RADIUS even with valid LDAP password");
            assertEquals(RadiusConstants.ACCESS_REJECT,
                    sendRadius("ldapuser", null, null).getCode(),
                    "Locked LDAP-backed account must be rejected on Out-of-Band RADIUS");
        }
    }

    private String[] ensureThreeDistinctSteps(String secret, long step) {
        String m1 = otpForStep(secret, step - 1);
        String c = otpForStep(secret, step);
        String p1 = otpForStep(secret, step + 1);
        assertFalse(m1.equals(c) && c.equals(p1));
        return new String[]{m1, c, p1};
    }

    @Test
    void crossChannelLockoutSharedAcrossAllChannels() throws Exception {
        long step = stableCurrentStep();
        String secret = distinctSecret(step);
        User alice = createUser("alice", PASSWORD, secret);
        String validOtp = otpForStep(secret, step);
        String wrongOtp = wrongOtpForStep(secret, step);
        String challenge = "12345678";
        String validOcra = ocraService.generateOcra(secret, challenge);

        // Accumulate 3 failures across 3 distinct channels using mixed identity forms
        assertFalse(postWebLogin("CORP\\AlIcE", "WrongPassword!", null).path("authenticated").asBoolean());
        assertFalse(postMfaPreAuth("alice@corp.local", Integer.parseInt(wrongOtp)));
        assertFalse(postValidateOtp(alice.getUsername(), Integer.parseInt(wrongOtp)));

        // Every channel must now reject alice even with completely valid credentials and unused codes
        assertFalse(postWebLogin("alice", PASSWORD, validOtp).path("authenticated").asBoolean(),
                "Locked user must be rejected on Web Login");
        assertFalse(postMfaPreAuth("alice", Integer.parseInt(validOtp)),
                "Locked user must be rejected on MFA Pre-Auth");
        assertFalse(postValidateOtp(alice.getUsername(), Integer.parseInt(validOtp)),
                "Locked user must be rejected on /v1/api/otp/validate");
        assertFalse(postValidateOcra(alice.getUsername(), challenge, validOcra),
                "Locked user must be rejected on /v1/api/otp/validate-ocra");
        assertEquals(RadiusConstants.ACCESS_REJECT, sendRadius("alice", PASSWORD, null).getCode(),
                "Locked user must be rejected on In-Band RADIUS");
        assertEquals(RadiusConstants.ACCESS_REJECT, sendRadius("CORP\\alice", PASSWORD, null).getCode(),
                "Locked user must be rejected on In-Band RADIUS with realm prefix");
        assertEquals(RadiusConstants.ACCESS_REJECT, sendRadius("alice", null, null).getCode(),
                "Locked user must be rejected on Out-of-Band RADIUS");

        // Secondary-factor failures (Web Login Step-2 invalid OTP, OCRA invalid OTP, RADIUS Challenge invalid OTP)
        // must accumulate toward the same shared threshold, and issuing ACCESS_CHALLENGE must not reset failures
        long step2 = stableCurrentStep();
        String secret2 = distinctSecret(step2);
        User aliceStep2 = createUser("alice-step2", PASSWORD, secret2);
        String validOtp2 = otpForStep(secret2, step2);
        String wrongOtp2 = wrongOtpForStep(secret2, step2);
        String validOcra2 = ocraService.generateOcra(secret2, "12345678");
        String wrongOcraOtp2 = String.format("%06d", (Integer.parseInt(validOcra2) + 123457) % 1_000_000);

        assertFalse(postWebLogin("CORP\\alice-step2", PASSWORD, wrongOtp2).path("authenticated").asBoolean());
        assertFalse(postValidateOcra(aliceStep2.getUsername(), "12345678", wrongOcraOtp2));
        byte[] step2Challenge = obtainChallengeState("alice-step2");
        assertEquals(RadiusConstants.ACCESS_REJECT,
                sendRadius("alice-step2@corp.local", wrongOtp2, step2Challenge).getCode());

        assertFalse(postWebLogin("alice-step2", PASSWORD, validOtp2).path("authenticated").asBoolean(),
                "Step-2 cross-channel failures must lock Web Login");
        assertFalse(postMfaPreAuth("alice-step2", Integer.parseInt(validOtp2)),
                "Step-2 cross-channel failures must lock MFA Pre-Auth");
        assertFalse(postValidateOtp(aliceStep2.getUsername(), Integer.parseInt(validOtp2)),
                "Step-2 cross-channel failures must lock /v1/api/otp/validate");
        assertFalse(postValidateOcra(aliceStep2.getUsername(), "12345678", validOcra2),
                "Step-2 cross-channel failures must lock /v1/api/otp/validate-ocra");
        assertEquals(RadiusConstants.ACCESS_REJECT, sendRadius("alice-step2", PASSWORD, null).getCode(),
                "Step-2 cross-channel failures must lock In-Band RADIUS");
        assertEquals(RadiusConstants.ACCESS_REJECT, sendRadius("alice-step2", null, null).getCode(),
                "Step-2 cross-channel failures must lock Out-of-Band RADIUS");
    }

    @Test
    void unapprovedOutOfBandRadiusRequestsTriggerCrossChannelLockout() throws Exception {
        long step = stableCurrentStep();
        String secret = distinctSecret(step);
        User bob = createUser("bob", PASSWORD, secret);
        String validOtp = otpForStep(secret, step);
        String validOcra = ocraService.generateOcra(secret, "87654321");

        // 3 unapproved out-of-band RADIUS requests (no password, no MfaApproval) reach maxFailures=3
        for (String variant : List.of("bob", "CORP\\bob", "bob@corp.local")) {
            assertEquals(RadiusConstants.ACCESS_REJECT, sendRadius(variant, null, null).getCode());
        }

        // Bob must now be blocked across all channels
        assertFalse(postWebLogin("bob", PASSWORD, validOtp).path("authenticated").asBoolean());
        assertFalse(postMfaPreAuth("bob", Integer.parseInt(validOtp)));
        assertFalse(postValidateOtp(bob.getUsername(), Integer.parseInt(validOtp)));
        assertFalse(postValidateOcra(bob.getUsername(), "87654321", validOcra));
        assertEquals(RadiusConstants.ACCESS_REJECT, sendRadius("bob", PASSWORD, null).getCode());
    }

    @Test
    void successfulAuthenticationClearsFailureAndLockoutStateAcrossChannels() throws Exception {
        long step = stableCurrentStep();
        String secret = distinctSecret(step);
        User carol = createUser("carol", PASSWORD, secret);
        String wrongOtp = wrongOtpForStep(secret, step);

        // Part A: 2 failures (<3) followed by 1 successful RADIUS auth clears failure counter
        assertFalse(postWebLogin("CORP\\carol", "wrong-pw", null).path("authenticated").asBoolean());
        assertFalse(postMfaPreAuth("carol", Integer.parseInt(wrongOtp)));

        byte[] state = obtainChallengeState("carol");
        assertEquals(RadiusConstants.ACCESS_ACCEPT, sendRadius("carol", otpForStep(secret, step - 1), state).getCode());

        // 2 more failures should NOT lock carol because the prior counter was cleared
        assertFalse(postValidateOtp(carol.getUsername(), Integer.parseInt(wrongOtp)));
        assertEquals(RadiusConstants.ACCESS_REJECT, sendRadius("carol", "wrong-pw", null).getCode());
        assertTrue(postWebLogin("carol", PASSWORD, otpForStep(secret, step)).path("authenticated").asBoolean(),
                "Counter must have been reset by successful authentication");

        // Part B: Reaching lockout, waiting for lockout expiration, and authenticating clears lockout state
        configurePolicy(3, 3, 2, 300, 2);
        String secret2 = distinctSecret(step);
        createUser("carol-expire", PASSWORD, secret2);
        String wrongOtp2 = wrongOtpForStep(secret2, step);
        assertFalse(postWebLogin("carol-expire", "wrong-pw", null).path("authenticated").asBoolean());
        assertFalse(postMfaPreAuth("carol-expire", Integer.parseInt(wrongOtp2)));
        assertEquals(RadiusConstants.ACCESS_REJECT, sendRadius("carol-expire", null, null).getCode());
        assertFalse(postWebLogin("carol-expire", PASSWORD, otpForStep(secret2, step)).path("authenticated").asBoolean(),
                "carol-expire must be locked immediately after 3rd failure");

        Thread.sleep(2300L);
        long postExpiryStep = stableCurrentStep();
        assertTrue(postWebLogin("carol-expire", PASSWORD, otpForStep(secret2, postExpiryStep)).path("authenticated").asBoolean(),
                "After lockout duration expires, valid login must succeed and clear lockout");

        // Verify counter reset after lockout recovery: 2 failures leave account unlocked on RADIUS
        assertFalse(postWebLogin("carol-expire", "wrong-pw", null).path("authenticated").asBoolean());
        assertFalse(postMfaPreAuth("carol-expire", Integer.parseInt(wrongOtpForStep(secret2, postExpiryStep))));
        assertEquals(RadiusConstants.ACCESS_CHALLENGE, sendRadius("carol-expire", PASSWORD, null).getCode());

        // Part C: Every authentication channel resets the shared failure state upon success
        configurePolicy(3, 3, 120, 300, 300);

        // 1. Web Login clears prior failures
        long webClrStep = stableCurrentStep();
        String webClrSec = distinctSecret(webClrStep);
        createUser("clr-web", PASSWORD, webClrSec);
        String webWrong = wrongOtpForStep(webClrSec, webClrStep);
        assertFalse(postWebLogin("CORP\\clr-web", "wrong-pw", null).path("authenticated").asBoolean());
        assertFalse(postMfaPreAuth("clr-web", Integer.parseInt(webWrong)));
        assertTrue(postWebLogin("clr-web", PASSWORD, otpForStep(webClrSec, webClrStep)).path("authenticated").asBoolean());
        assertEquals(RadiusConstants.ACCESS_REJECT, sendRadius("clr-web", "wrong-pw", null).getCode());
        assertFalse(postMfaPreAuth("clr-web", Integer.parseInt(webWrong)));
        assertEquals(RadiusConstants.ACCESS_CHALLENGE, sendRadius("clr-web", PASSWORD, null).getCode(),
                "Web Login success must clear shared failure counter");

        // 2. MFA Pre-Auth clears prior failures
        long mfaClrStep = stableCurrentStep();
        String mfaClrSec = distinctSecret(mfaClrStep);
        createUser("clr-mfa", PASSWORD, mfaClrSec);
        String mfaWrong = wrongOtpForStep(mfaClrSec, mfaClrStep);
        assertFalse(postWebLogin("clr-mfa", "wrong-pw", null).path("authenticated").asBoolean());
        assertEquals(RadiusConstants.ACCESS_REJECT, sendRadius("CORP\\clr-mfa", "wrong-pw", null).getCode());
        assertTrue(postMfaPreAuth("clr-mfa", Integer.parseInt(otpForStep(mfaClrSec, mfaClrStep))));
        assertFalse(postWebLogin("clr-mfa", "wrong-pw", null).path("authenticated").asBoolean());
        assertFalse(postMfaPreAuth("clr-mfa", Integer.parseInt(mfaWrong)));
        assertEquals(RadiusConstants.ACCESS_CHALLENGE, sendRadius("clr-mfa", PASSWORD, null).getCode(),
                "MFA Pre-Auth success must clear shared failure counter");

        // 3. Out-of-Band RADIUS clears prior failures (accumulated between pre-auth and RADIUS consume)
        long oobClrStep = stableCurrentStep();
        String oobClrSec = distinctSecret(oobClrStep);
        createUser("clr-oob", PASSWORD, oobClrSec);
        assertTrue(postMfaPreAuth("clr-oob", Integer.parseInt(otpForStep(oobClrSec, oobClrStep))));
        assertFalse(postWebLogin("CORP\\clr-oob", "wrong-pw", null).path("authenticated").asBoolean());
        assertEquals(RadiusConstants.ACCESS_REJECT, sendRadius("clr-oob", "wrong-pw", null).getCode());
        assertEquals(RadiusConstants.ACCESS_ACCEPT, sendRadius("CORP\\clr-oob", null, null).getCode(),
                "Out-of-Band RADIUS should succeed despite <maxFailures mismatched failures");
        assertFalse(postWebLogin("clr-oob", "wrong-pw", null).path("authenticated").asBoolean());
        assertFalse(postMfaPreAuth("clr-oob", Integer.parseInt(wrongOtpForStep(oobClrSec, oobClrStep))));
        assertEquals(RadiusConstants.ACCESS_CHALLENGE, sendRadius("clr-oob", PASSWORD, null).getCode(),
                "Out-of-Band RADIUS success must clear shared failure counter");

        // 4. Direct /v1/api/otp/validate clears prior failures
        long otpClrStep = stableCurrentStep();
        String otpClrSec = distinctSecret(otpClrStep);
        User otpClrUser = createUser("clr-otp", PASSWORD, otpClrSec);
        assertFalse(postWebLogin("clr-otp", "wrong-pw", null).path("authenticated").asBoolean());
        assertFalse(postMfaPreAuth("clr-otp", Integer.parseInt(wrongOtpForStep(otpClrSec, otpClrStep))));
        assertTrue(postValidateOtp(otpClrUser.getUsername(), Integer.parseInt(otpForStep(otpClrSec, otpClrStep))));
        assertEquals(RadiusConstants.ACCESS_REJECT, sendRadius("clr-otp", "wrong-pw", null).getCode());
        assertFalse(postWebLogin("clr-otp", "wrong-pw", null).path("authenticated").asBoolean());
        assertEquals(RadiusConstants.ACCESS_CHALLENGE, sendRadius("clr-otp", PASSWORD, null).getCode(),
                "/v1/api/otp/validate success must clear shared failure counter");

        // 5. Direct /v1/api/otp/validate-ocra clears prior failures
        long ocraClrStep = stableCurrentStep();
        String ocraClrSec = distinctSecret(ocraClrStep);
        User ocraClrUser = createUser("clr-ocra", PASSWORD, ocraClrSec);
        assertFalse(postWebLogin("clr-ocra", "wrong-pw", null).path("authenticated").asBoolean());
        assertEquals(RadiusConstants.ACCESS_REJECT, sendRadius("clr-ocra", "wrong-pw", null).getCode());
        assertTrue(postValidateOcra(ocraClrUser.getUsername(), "13572468",
                ocraService.generateOcra(ocraClrSec, "13572468")));
        assertFalse(postMfaPreAuth("clr-ocra", Integer.parseInt(wrongOtpForStep(ocraClrSec, ocraClrStep))));
        assertFalse(postValidateOtp(ocraClrUser.getUsername(), Integer.parseInt(wrongOtpForStep(ocraClrSec, ocraClrStep))));
        assertEquals(RadiusConstants.ACCESS_CHALLENGE, sendRadius("clr-ocra", PASSWORD, null).getCode(),
                "/v1/api/otp/validate-ocra success must clear shared failure counter");
    }

    @Test
    void totpSingleUseAndStrictMonotonicTimeStepAcrossChannels() throws Exception {
        configurePolicy(50, 50, 120, 300, 300);
        long stepT = stableCurrentStep();
        String secret1 = distinctSecret(stepT);
        User alice = createUser("mono-alice", PASSWORD, secret1);
        String otpT = otpForStep(secret1, stepT);
        String otpTMinus1 = otpForStep(secret1, stepT - 1);
        String otpTPlus1 = otpForStep(secret1, stepT + 1);

        // Consume step T on Web Login
        assertTrue(postWebLogin("mono-alice", PASSWORD, otpT).path("authenticated").asBoolean());

        // Replaying exact step T must fail on every channel
        assertFalse(postWebLogin("mono-alice", PASSWORD, otpT).path("authenticated").asBoolean());
        assertFalse(postMfaPreAuth("mono-alice", Integer.parseInt(otpT)));
        assertFalse(postValidateOtp(alice.getUsername(), Integer.parseInt(otpT)));
        byte[] stateReplayT = obtainChallengeState("mono-alice");
        assertEquals(RadiusConstants.ACCESS_REJECT, sendRadius("mono-alice", otpT, stateReplayT).getCode());

        // Submitting older within-drift step T-1 AFTER T succeeded must also fail on every channel
        assertFalse(postWebLogin("mono-alice", PASSWORD, otpTMinus1).path("authenticated").asBoolean(),
                "Older time step T-1 must be rejected after step T was accepted");
        assertFalse(postMfaPreAuth("mono-alice", Integer.parseInt(otpTMinus1)),
                "Older time step T-1 must be rejected on MFA Pre-Auth after step T was accepted");
        assertFalse(postValidateOtp(alice.getUsername(), Integer.parseInt(otpTMinus1)),
                "Older time step T-1 must be rejected on /v1/api/otp/validate after step T was accepted");
        byte[] stateOlder = obtainChallengeState("mono-alice");
        assertEquals(RadiusConstants.ACCESS_REJECT, sendRadius("mono-alice", otpTMinus1, stateOlder).getCode(),
                "Older time step T-1 must be rejected on RADIUS after step T was accepted");

        // Strictly newer step T+1 (> T) must still succeed
        byte[] stateNewer = obtainChallengeState("mono-alice");
        assertEquals(RadiusConstants.ACCESS_ACCEPT, sendRadius("mono-alice", otpTPlus1, stateNewer).getCode());

        // Fresh user going in forward chronological order (T-1 then T) succeeds at each step
        String secret2 = distinctSecret(stepT);
        createUser("mono-bob", PASSWORD, secret2);
        assertTrue(postMfaPreAuth("mono-bob", Integer.parseInt(otpForStep(secret2, stepT - 1))));
        assertTrue(postMfaPreAuth("mono-bob", Integer.parseInt(otpForStep(secret2, stepT))));
        assertFalse(postMfaPreAuth("mono-bob", Integer.parseInt(otpForStep(secret2, stepT))));
    }

    @Test
    void ocraSingleUseAndLockoutIntegration() throws Exception {
        long step = stableCurrentStep();
        String secret = distinctSecret(step);
        User u = createUser("ocra-user", PASSWORD, secret);
        String ch1 = "12345678";
        String ch2 = "87654321";
        String ocra1 = ocraService.generateOcra(secret, ch1);
        String ocra2 = ocraService.generateOcra(secret, ch2);

        // First OCRA validation succeeds
        assertTrue(postValidateOcra(u.getUsername(), ch1, ocra1));
        // Second validation of the same challenge + code fails (single-use)
        assertFalse(postValidateOcra(u.getUsername(), ch1, ocra1), "Replaying consumed OCRA code must be rejected");
        // Another valid challenge still works (unless locked out — we still have < maxFailures=3)
        assertTrue(postValidateOcra(u.getUsername(), ch2, ocra2));

        // Concurrently submitting a valid OCRA challenge across 4 threads allows only 1 winner
        String ch3 = "55667788";
        String ocra3 = ocraService.generateOcra(secret, ch3);
        ExecutorService pool = Executors.newFixedThreadPool(4);
        try {
            CountDownLatch ready = new CountDownLatch(4);
            CountDownLatch go = new CountDownLatch(1);
            List<Future<Boolean>> futures = new ArrayList<>();
            for (int i = 0; i < 4; i++) {
                futures.add(pool.submit(() -> {
                    ready.countDown();
                    go.await();
                    return userOtpService.validateUserOcra(u.getId(), ch3, ocra3).orElse(false);
                }));
            }
            assertTrue(ready.await(5, TimeUnit.SECONDS));
            go.countDown();
            int successes = 0;
            for (Future<Boolean> f : futures) {
                if (Boolean.TRUE.equals(f.get(10, TimeUnit.SECONDS))) {
                    successes++;
                }
            }
            assertEquals(1, successes, "Concurrent OCRA validation must accept exactly once");
        } finally {
            pool.shutdownNow();
        }

        // Now repeated OCRA replay/invalid attempts count toward shared cross-channel lockout
        String ch4 = "99887766";
        String ocra4 = ocraService.generateOcra(secret, ch4);
        assertFalse(postValidateOcra(u.getUsername(), ch1, "000000"));
        assertFalse(postValidateOcra(u.getUsername(), ch1, "000000"));
        assertFalse(postValidateOcra(u.getUsername(), ch1, "000000"));
        assertFalse(postValidateOcra(u.getUsername(), ch4, ocra4), "Locked user must be rejected on OCRA even for fresh challenge");
        assertEquals(RadiusConstants.ACCESS_REJECT, sendRadius("ocra-user", PASSWORD, null).getCode(),
                "OCRA failure lockout must propagate to RADIUS");
    }

    @Test
    void concurrentCrossChannelVerificationAndClusterPersistence() throws Exception {
        configurePolicy(50, 50, 120, 300, 300);
        long step = stableCurrentStep();
        String raceSecret = distinctSecret(step);
        String otpT = otpForStep(raceSecret, step);
        User raceAlice = createUser("race-alice", PASSWORD, raceSecret);
        byte[] stateA1 = obtainChallengeState("race-alice");
        byte[] stateA2 = obtainChallengeState("race-alice");

        // Part A: 6-way concurrent verification across all OTP-consuming channels -> exactly 1 winner
        ExecutorService pool = Executors.newFixedThreadPool(6);
        try {
            CountDownLatch ready = new CountDownLatch(6);
            CountDownLatch go = new CountDownLatch(1);
            List<Callable<Boolean>> tasks = List.of(
                    () -> {
                        ready.countDown();
                        go.await();
                        return loginService.login(LoginRequest.builder()
                                .username("race-alice").password(PASSWORD).otp(otpT).build()).isAuthenticated();
                    },
                    () -> {
                        ready.countDown();
                        go.await();
                        return loginService.login(LoginRequest.builder()
                                .username("race-alice").password(PASSWORD).otp(otpT).build()).isAuthenticated();
                    },
                    () -> {
                        ready.countDown();
                        go.await();
                        return mfaPreAuthService.preAuthenticate("race-alice", Integer.parseInt(otpT));
                    },
                    () -> {
                        ready.countDown();
                        go.await();
                        return userOtpService.validateUserOtp(raceAlice.getId(), Integer.parseInt(otpT)).orElse(false);
                    },
                    () -> {
                        ready.countDown();
                        go.await();
                        return sendRadius("race-alice", otpT, stateA1).getCode() == RadiusConstants.ACCESS_ACCEPT;
                    },
                    () -> {
                        ready.countDown();
                        go.await();
                        return sendRadius("race-alice", otpT, stateA2).getCode() == RadiusConstants.ACCESS_ACCEPT;
                    }
            );
            List<Future<Boolean>> futures = new ArrayList<>();
            for (Callable<Boolean> task : tasks) {
                futures.add(pool.submit(task));
            }
            assertTrue(ready.await(5, TimeUnit.SECONDS));
            go.countDown();

            int accepts = 0;
            for (Future<Boolean> f : futures) {
                if (Boolean.TRUE.equals(f.get(10, TimeUnit.SECONDS))) {
                    accepts++;
                }
            }
            assertEquals(1, accepts, "Concurrent cross-channel TOTP attempts must allow exactly 1 winner");
        } finally {
            pool.shutdownNow();
        }

        // Concurrent T vs T-1 skew-window race across channels: T must always succeed, and both T and T-1 are blocked afterward
        for (int i = 0; i < 4; i++) {
            long skewStep = stableCurrentStep();
            String skewSecret = distinctSecret(skewStep);
            String skewOtpT = otpForStep(skewSecret, skewStep);
            String skewOtpTMinus1 = otpForStep(skewSecret, skewStep - 1);
            assertNotEquals(skewOtpT, skewOtpTMinus1);

            String uname = "race-skew-" + i;
            User skewUser = createUser(uname, PASSWORD, skewSecret);
            boolean useRadius = (i % 2 == 0);
            byte[] skewChallenge = useRadius ? obtainChallengeState(uname) : null;

            ExecutorService skewPool = Executors.newFixedThreadPool(2);
            try {
                CountDownLatch ready = new CountDownLatch(2);
                CountDownLatch go = new CountDownLatch(1);
                Future<Boolean> fWebT = skewPool.submit(() -> {
                    ready.countDown();
                    go.await();
                    return loginService.login(LoginRequest.builder()
                            .username(uname).password(PASSWORD).otp(skewOtpT).build()).isAuthenticated();
                });
                Future<Boolean> fOtherMinus1 = skewPool.submit(() -> {
                    ready.countDown();
                    go.await();
                    if (useRadius) {
                        return sendRadius(uname, skewOtpTMinus1, skewChallenge).getCode() == RadiusConstants.ACCESS_ACCEPT;
                    }
                    return mfaPreAuthService.preAuthenticate(uname, Integer.parseInt(skewOtpTMinus1));
                });
                assertTrue(ready.await(5, TimeUnit.SECONDS));
                go.countDown();

                assertTrue(fWebT.get(10, TimeUnit.SECONDS),
                        "Newer step T must always succeed even when T-1 races concurrently");
                assertNotNull(fOtherMinus1.get(10, TimeUnit.SECONDS));
            } finally {
                skewPool.shutdownNow();
            }

            assertFalse(postWebLogin(uname, PASSWORD, skewOtpT).path("authenticated").asBoolean());
            assertFalse(postWebLogin(uname, PASSWORD, skewOtpTMinus1).path("authenticated").asBoolean());
            assertFalse(postMfaPreAuth(uname, Integer.parseInt(skewOtpT)));
            assertFalse(postMfaPreAuth(uname, Integer.parseInt(skewOtpTMinus1)));
            assertFalse(postValidateOtp(skewUser.getUsername(), Integer.parseInt(skewOtpT)));
            assertFalse(postValidateOtp(skewUser.getUsername(), Integer.parseInt(skewOtpTMinus1)));
            byte[] postSt1 = obtainChallengeState(uname);
            assertEquals(RadiusConstants.ACCESS_REJECT, sendRadius(uname, skewOtpT, postSt1).getCode());
            byte[] postSt2 = obtainChallengeState(uname);
            assertEquals(RadiusConstants.ACCESS_REJECT, sendRadius(uname, skewOtpTMinus1, postSt2).getCode());
        }

        // Part B: Two separate Spring contexts sharing one DB + an isolated context on a separate DB (verifying DB-backed, non-static state)
        String dbUrl = "jdbc:h2:mem:iamcluster_" + UUID.randomUUID().toString().replace("-", "") + ";DB_CLOSE_DELAY=-1";
        String isolatedDbUrl = "jdbc:h2:mem:iamisolated_" + UUID.randomUUID().toString().replace("-", "") + ";DB_CLOSE_DELAY=-1";
        try (ConfigurableApplicationContext node1 = startClusterNode(dbUrl);
             ConfigurableApplicationContext node2 = startClusterNode(dbUrl);
             ConfigurableApplicationContext isolatedNode = startClusterNode(isolatedDbUrl)) {

            long clusterStep = stableCurrentStep();
            String cSecret = distinctSecret(clusterStep);
            String cPrev = otpForStep(cSecret, clusterStep - 1);
            String cCurr = otpForStep(cSecret, clusterStep);

            User clusterUser = node1.getBean(UserService.class).saveUser(User.builder()
                    .username("cluster-alice").password(PASSWORD).secret(cSecret).build());
            User isolatedUser = isolatedNode.getBean(UserService.class).saveUser(User.builder()
                    .username("cluster-alice").password(PASSWORD).secret(cSecret).build());

            // 1. TOTP step T accepted on node1 blocks both T and T-1 on node2 across channels, but NOT on an isolated DB
            assertTrue(node1.getBean(LoginService.class).login(LoginRequest.builder()
                    .username("cluster-alice").password(PASSWORD).otp(cCurr).build()).isAuthenticated());
            assertFalse(node2.getBean(MfaPreAuthService.class).preAuthenticate("cluster-alice", Integer.parseInt(cCurr)),
                    "Node 2 must reject OTP T already consumed on Node 1");
            assertFalse(node2.getBean(UserOtpService.class).validateUserOtp(clusterUser.getId(), Integer.parseInt(cPrev))
                    .orElse(false), "Node 2 must reject older OTP T-1 after Node 1 accepted T");
            assertTrue(isolatedNode.getBean(LoginService.class).login(LoginRequest.builder()
                    .username("cluster-alice").password(PASSWORD).otp(cCurr).build()).isAuthenticated(),
                    "State must live in the database, not in JVM static fields shared across independent databases");

            // 2. OCRA consumed on node1 is rejected on node2, but NOT on an isolated DB
            String ocraCh = "24681357";
            String ocraCode = node1.getBean(OcraService.class).generateOcra(cSecret, ocraCh);
            assertTrue(node1.getBean(UserOtpService.class).validateUserOcra(clusterUser.getId(), ocraCh, ocraCode)
                    .orElse(false));
            assertFalse(node2.getBean(UserOtpService.class).validateUserOcra(clusterUser.getId(), ocraCh, ocraCode)
                    .orElse(false), "Node 2 must reject OCRA consumed on Node 1");
            assertTrue(isolatedNode.getBean(UserOtpService.class).validateUserOcra(isolatedUser.getId(), ocraCh, ocraCode)
                    .orElse(false), "OCRA replay state must live in the database, not in JVM static fields");

            // 3. RADIUS Access-Challenge issued by node1 is rejected by isolatedNode, and accepted by node2
            int port1 = node1.getBean(RadiusServer.class).getLocalPort();
            int port2 = node2.getBean(RadiusServer.class).getLocalPort();
            int isolatedPort = isolatedNode.getBean(RadiusServer.class).getLocalPort();
            byte[] clusterState = obtainChallengeState(port1, "cluster-secret", "cluster-alice", PASSWORD);
            assertEquals(RadiusConstants.ACCESS_REJECT,
                    sendRadius(isolatedPort, "cluster-secret", "cluster-alice", otpForStep(cSecret, clusterStep + 1), clusterState).getCode(),
                    "Pending RADIUS challenges must live in the database, not in JVM static fields");
            assertEquals(RadiusConstants.ACCESS_ACCEPT,
                    sendRadius(port2, "cluster-secret", "cluster-alice", otpForStep(cSecret, clusterStep + 1), clusterState).getCode(),
                    "Node 2 must accept RADIUS challenge issued by Node 1");

            // 4. Failures spread across node1 and node2 trigger shared lockout visible to both nodes, without leaking via JVM statics
            User lockUser = node1.getBean(UserService.class).saveUser(User.builder()
                    .username("cluster-lock").password(PASSWORD).secret(cSecret).build());
            isolatedNode.getBean(UserService.class).saveUser(User.builder()
                    .username("cluster-lock").password(PASSWORD).secret(cSecret).build());
            assertFalse(node1.getBean(LoginService.class).login(LoginRequest.builder()
                    .username("cluster-lock").password("bad").build()).isAuthenticated());
            assertFalse(node2.getBean(MfaPreAuthService.class).preAuthenticate("cluster-lock", 999999));
            assertEquals(RadiusConstants.ACCESS_REJECT,
                    sendRadius(port1, "cluster-secret", "cluster-lock", null, null).getCode());

            // Account is now locked on BOTH nodes sharing dbUrl, while independent DB remains unlocked
            String freshCode = otpForStep(cSecret, stableCurrentStep());
            assertFalse(node2.getBean(LoginService.class).login(LoginRequest.builder()
                    .username("cluster-lock").password(PASSWORD).otp(freshCode).build()).isAuthenticated());
            assertEquals(RadiusConstants.ACCESS_REJECT,
                    sendRadius(port2, "cluster-secret", "cluster-lock", PASSWORD, null).getCode());
            assertFalse(node1.getBean(UserOtpService.class).validateUserOtp(lockUser.getId(), Integer.parseInt(freshCode))
                    .orElse(false));
            assertTrue(isolatedNode.getBean(LoginService.class).login(LoginRequest.builder()
                    .username("cluster-lock").password(PASSWORD).otp(freshCode).build()).isAuthenticated(),
                    "Lockout state must live in the database, not in JVM static fields");
        }

        // Part C: Concurrent cross-channel failure race atomically tracks all failures, locks account, and invalidates pending sessions
        configurePolicy(3, 3, 120, 300, 300);
        for (int i = 0; i < 4; i++) {
            long failStep = stableCurrentStep();
            String failSecret = distinctSecret(failStep);
            String uname = "race-fail-" + i;
            User failUser = createUser(uname, PASSWORD, failSecret);
            String[] codes = ensureThreeDistinctSteps(failSecret, failStep);
            String wrongOtp = wrongOtpForStep(failSecret, failStep);

            assertTrue(postMfaPreAuth(uname, Integer.parseInt(codes[0])));
            assertTrue(mfaPreAuthService.hasActiveApproval(uname));
            byte[] pendingState = obtainChallengeState(uname);

            ExecutorService failPool = Executors.newFixedThreadPool(3);
            try {
                CountDownLatch ready = new CountDownLatch(3);
                CountDownLatch go = new CountDownLatch(1);
                Future<Boolean> fWeb = failPool.submit(() -> {
                    ready.countDown();
                    go.await();
                    return loginService.login(LoginRequest.builder()
                            .username(uname).password("wrong-pw-" + Thread.currentThread().getId()).build()).isAuthenticated();
                });
                Future<Boolean> fMfa = failPool.submit(() -> {
                    ready.countDown();
                    go.await();
                    return mfaPreAuthService.preAuthenticate(uname, Integer.parseInt(wrongOtp));
                });
                Future<Integer> fRad = failPool.submit(() -> {
                    ready.countDown();
                    go.await();
                    return sendRadius("CORP\\" + uname, "wrong-pw", null).getCode();
                });
                assertTrue(ready.await(5, TimeUnit.SECONDS));
                go.countDown();

                assertFalse(fWeb.get(10, TimeUnit.SECONDS));
                assertFalse(fMfa.get(10, TimeUnit.SECONDS));
                assertEquals(RadiusConstants.ACCESS_REJECT, fRad.get(10, TimeUnit.SECONDS));
            } finally {
                failPool.shutdownNow();
            }

            assertFalse(mfaPreAuthService.hasActiveApproval(uname),
                    "Concurrent lockout must invalidate pending MFA approval");
            assertEquals(RadiusConstants.ACCESS_REJECT, sendRadius(uname, codes[1], pendingState).getCode(),
                    "Invalidated RADIUS challenge must be rejected after concurrent lockout");

            assertFalse(postWebLogin(uname, PASSWORD, codes[1]).path("authenticated").asBoolean(),
                    "Account locked via concurrent failures must be blocked on Web Login");
            assertFalse(postMfaPreAuth(uname, Integer.parseInt(codes[2])),
                    "Account locked via concurrent failures must be blocked on MFA Pre-Auth");
            assertFalse(postValidateOtp(failUser.getUsername(), Integer.parseInt(codes[2])),
                    "Account locked via concurrent failures must be blocked on /v1/api/otp/validate");
            assertEquals(RadiusConstants.ACCESS_REJECT, sendRadius(uname, PASSWORD, null).getCode(),
                    "Account locked via concurrent failures must be blocked on In-Band RADIUS");
            assertEquals(RadiusConstants.ACCESS_REJECT, sendRadius(uname, null, null).getCode(),
                    "Account locked via concurrent failures must be blocked on Out-of-Band RADIUS");
        }
    }

    private ConfigurableApplicationContext startClusterNode(String dbUrl) {
        return new SpringApplicationBuilder(IamApplication.class).run(
                "--server.port=0",
                "--spring.jmx.enabled=false",
                "--radius.enabled=true",
                "--radius.port=0",
                "--radius.bind-address=127.0.0.1",
                "--iam.bootstrap.radius.shared-secret=cluster-secret",
                "--iam.bootstrap.policy.max-failures=3",
                "--iam.bootstrap.policy.lockout-seconds=120",
                "--spring.datasource.url=" + dbUrl,
                "--spring.jpa.hibernate.ddl-auto=update");
    }

    @Test
    @WithMockUser
    void nonDestructiveMismatchAndSessionInvalidationOnAccountLifecycleEvents() throws Exception {
        long step = stableCurrentStep();
        String aliceSecret = distinctSecret(step);
        createUser("alice", PASSWORD, aliceSecret);
        createUser("bob", PASSWORD, distinctSecret(step));

        String otpMinus1 = otpForStep(aliceSecret, step - 1);
        String otpCurrent = otpForStep(aliceSecret, step);
        String otpPlus1 = otpForStep(aliceSecret, step + 1);

        // 1. Mismatched client IP and mismatched username do NOT destroy alice's pending RADIUS challenge
        byte[] aliceState = obtainChallengeState("alice");

        byte[] wrongIpReq = buildSignedRadiusPacket("alice", otpMinus1, aliceState);
        byte[] wrongIpResp = radiusHandler.handle(
                RadiusPacket.decode(wrongIpReq, wrongIpReq.length), InetAddress.getByName("10.9.8.7")).orElseThrow();
        assertEquals(RadiusConstants.ACCESS_REJECT, wrongIpResp[0] & 0xFF,
                "IP mismatch must be rejected with ACCESS_REJECT");

        assertEquals(RadiusConstants.ACCESS_REJECT, sendRadius("bob", otpMinus1, aliceState).getCode(),
                "Username mismatch must be rejected with ACCESS_REJECT");
        assertEquals(RadiusConstants.ACCESS_REJECT, sendRadius("CORP\\bob", otpMinus1, aliceState).getCode(),
                "Qualified username mismatch must be rejected with ACCESS_REJECT");

        assertEquals(RadiusConstants.ACCESS_ACCEPT, sendRadius("CORP\\alice", otpMinus1, aliceState).getCode(),
                "Legitimate user must still complete the preserved RADIUS challenge");
        assertEquals(RadiusConstants.ACCESS_REJECT, sendRadius("CORP\\alice", otpPlus1, aliceState).getCode(),
                "Completed RADIUS challenge State must be single-use");

        // 2. Out-of-band MFA attempts for bob do NOT destroy alice's pending MFA approval
        assertTrue(postMfaPreAuth("AlIcE", Integer.parseInt(otpCurrent)));
        assertEquals(RadiusConstants.ACCESS_REJECT, sendRadius("bob", null, null).getCode());
        assertEquals(RadiusConstants.ACCESS_REJECT, sendRadius("CORP\\bob", null, null).getCode());
        assertTrue(mfaPreAuthService.hasActiveApproval("alice"),
                "Out-of-band attempts for another user must preserve alice's active MFA approval");
        assertEquals(RadiusConstants.ACCESS_ACCEPT, sendRadius("CORP\\alice", null, null).getCode());
        assertFalse(mfaPreAuthService.hasActiveApproval("alice"),
                "Consumed MFA approval must no longer be active");
        assertEquals(RadiusConstants.ACCESS_REJECT, sendRadius("CORP\\alice", null, null).getCode());

        // 3. Password change immediately invalidates pending MFA approval & RADIUS challenge
        String pwSecret = distinctSecret(step);
        User pwUser = createUser("pw-user", PASSWORD, pwSecret);
        assertTrue(postMfaPreAuth("pw-user", Integer.parseInt(otpForStep(pwSecret, step))));
        byte[] pwChallengeState = obtainChallengeState("pw-user");
        assertTrue(mfaPreAuthService.hasActiveApproval("pw-user"));

        mockMvc.perform(put("/v1/api/users/" + pwUser.getId())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"pw-user\",\"password\":\"NewPass!999\",\"secret\":\"" + pwSecret + "\"}"))
                .andExpect(status().is2xxSuccessful());

        assertFalse(mfaPreAuthService.hasActiveApproval("pw-user"),
                "Password change must invalidate pending MFA approval");
        assertEquals(RadiusConstants.ACCESS_REJECT,
                sendRadius("pw-user", otpForStep(pwSecret, step + 1), pwChallengeState).getCode(),
                "Password change must invalidate pending RADIUS challenge");
        assertEquals(RadiusConstants.ACCESS_REJECT,
                sendRadius("pw-user", null, null).getCode(),
                "Out-of-Band RADIUS must be rejected after password change invalidates approval");

        // 4. OTP secret change invalidates pending approval and challenge, while codes under the new secret work
        long rotStep = stableCurrentStep();
        String rotSecret = distinctSecret(rotStep);
        User rotUser = createUser("rot-user", PASSWORD, rotSecret);
        assertTrue(postMfaPreAuth("rot-user", Integer.parseInt(otpForStep(rotSecret, rotStep - 1))));
        byte[] rotState = obtainChallengeState("rot-user");

        String rotatedSecret = mockMvc.perform(post("/v1/api/otp/generate/" + rotUser.getUsername()))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString().trim();
        assertNotEquals(rotSecret, rotatedSecret);
        assertFalse(mfaPreAuthService.hasActiveApproval("rot-user"),
                "OTP secret modification must invalidate pending MFA approval");
        assertEquals(RadiusConstants.ACCESS_REJECT,
                sendRadius("rot-user", null, null).getCode(),
                "Out-of-Band RADIUS must be rejected after OTP secret rotation");
        assertEquals(RadiusConstants.ACCESS_REJECT,
                sendRadius("rot-user", otpForStep(rotatedSecret, rotStep), rotState).getCode(),
                "Pending RADIUS challenge issued before secret rotation must be rejected even with an OTP from the new secret");

        String codeFromNewSecret = otpForStep(rotatedSecret, rotStep + 1);
        assertTrue(postMfaPreAuth("rot-user", Integer.parseInt(codeFromNewSecret)),
                "Fresh OTP under newly rotated secret must be accepted on the next time step");
        assertTrue(mfaPreAuthService.consumeApproval("rot-user"));

        // 4b. Modifying OTP secret via user update immediately invalidates pending MFA approval and RADIUS challenge
        long remStep = stableCurrentStep();
        String remSecret = distinctSecret(remStep);
        User remUser = createUser("rem-user", PASSWORD, remSecret);
        assertTrue(postMfaPreAuth("rem-user", Integer.parseInt(otpForStep(remSecret, remStep))));
        assertTrue(mfaPreAuthService.hasActiveApproval("rem-user"));
        byte[] remState = obtainChallengeState("rem-user");

        String newRemSecret = secretGenerator.generateSecret();
        while (newRemSecret.equals(remSecret)) {
            newRemSecret = secretGenerator.generateSecret();
        }
        User remReloaded = userService.getUserById(remUser.getId());
        remReloaded.setSecret(newRemSecret);
        userService.saveUser(remReloaded);

        assertFalse(mfaPreAuthService.hasActiveApproval("rem-user"),
                "Modifying OTP secret via user update must immediately invalidate pending MFA approval");
        assertEquals(RadiusConstants.ACCESS_REJECT,
                sendRadius("rem-user", otpForStep(newRemSecret, remStep + 1), remState).getCode(),
                "Stale RADIUS challenge must be rejected after OTP secret is modified, even with an OTP from the new secret");
        assertEquals(RadiusConstants.ACCESS_REJECT,
                sendRadius("rem-user", null, null).getCode(),
                "Out-of-Band RADIUS must be rejected after OTP secret is modified");

        // 5. Cross-channel lockout immediately invalidates pending MFA approval and RADIUS challenge
        String lockSecret = distinctSecret(step);
        createUser("lock-inval", PASSWORD, lockSecret);
        assertTrue(postMfaPreAuth("lock-inval", Integer.parseInt(otpForStep(lockSecret, step))));
        byte[] lockState = obtainChallengeState("lock-inval");
        for (int i = 0; i < 3; i++) {
            assertFalse(postWebLogin("lock-inval", "Wrong!Pass", null).path("authenticated").asBoolean());
        }
        assertFalse(mfaPreAuthService.hasActiveApproval("lock-inval"),
                "Account lockout must invalidate pending MFA approval");
        assertEquals(RadiusConstants.ACCESS_REJECT,
                sendRadius("lock-inval", otpForStep(lockSecret, step + 1), lockState).getCode(),
                "Account lockout must invalidate pending RADIUS challenge");
        assertEquals(RadiusConstants.ACCESS_REJECT, sendRadius("lock-inval", null, null).getCode());

        // 6. Account deletion immediately invalidates pending MFA approval and RADIUS challenge
        String delSecret = distinctSecret(step);
        User delUser = createUser("del-user", PASSWORD, delSecret);
        assertTrue(postMfaPreAuth("del-user", Integer.parseInt(otpForStep(delSecret, step))));
        byte[] delState = obtainChallengeState("del-user");

        mockMvc.perform(delete("/v1/api/users/" + delUser.getId()))
                .andExpect(status().is2xxSuccessful());

        assertFalse(mfaPreAuthService.hasActiveApproval("del-user"),
                "Account deletion must invalidate pending MFA approval");
        assertEquals(RadiusConstants.ACCESS_REJECT,
                sendRadius("del-user", otpForStep(delSecret, step + 1), delState).getCode(),
                "Account deletion must invalidate pending RADIUS challenge");
        assertEquals(RadiusConstants.ACCESS_REJECT, sendRadius("del-user", null, null).getCode());
    }

    @Test
    @WithMockUser
    void realmQualifiedLocalAccountsIsolateApprovalsChallengesAndLifecycleEvents() throws Exception {
        long step = stableCurrentStep();
        String aliceSecret = distinctSecret(step);
        String partnerSecret = distinctSecret(step);

        MvcResult createAlice = mockMvc.perform(post("/v1/api/users/create")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice\",\"password\":\"" + PASSWORD
                                + "\",\"secret\":\"" + aliceSecret + "\"}"))
                .andExpect(status().is2xxSuccessful())
                .andReturn();
        MvcResult createPartner = mockMvc.perform(post("/v1/api/users/create")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice@partner.example\",\"password\":\"" + PASSWORD
                                + "\",\"secret\":\"" + partnerSecret + "\"}"))
                .andExpect(status().is2xxSuccessful())
                .andReturn();

        long aliceId = JSON.readTree(createAlice.getResponse().getContentAsString()).path("id").asLong();
        long partnerId = JSON.readTree(createPartner.getResponse().getContentAsString()).path("id").asLong();
        assertTrue(aliceId > 0);
        assertTrue(partnerId > 0);
        assertNotEquals(aliceId, partnerId,
                "Canonical 'alice' and realm-qualified 'alice@partner.example' must be distinct local accounts");
        assertEquals(2, userRepository.count());

        // 1. Out-of-band MFA approval and unapproved attempts for alice@partner.example remain isolated from alice
        assertTrue(postMfaPreAuth("alice", Integer.parseInt(otpForStep(aliceSecret, step - 1))));
        assertEquals(RadiusConstants.ACCESS_REJECT, sendRadius("alice@partner.example", null, null).getCode(),
                "Unapproved realm-distinct account must not consume or share alice's MFA approval");
        assertTrue(mfaPreAuthService.hasActiveApproval("alice"),
                "Rejected OOB request for alice@partner.example must leave alice's active approval intact");
        assertEquals(RadiusConstants.ACCESS_ACCEPT, sendRadius("CORP\\alice", null, null).getCode(),
                "Qualified login CORP\\alice (with no dedicated local account) must resolve to canonical alice");

        // 2. In-band RADIUS challenge State issued for alice cannot be hijacked or destroyed by alice@partner.example
        byte[] aliceState = obtainChallengeState("alice");
        assertEquals(RadiusConstants.ACCESS_REJECT,
                sendRadius("alice@partner.example", otpForStep(aliceSecret, step), aliceState).getCode(),
                "Realm-distinct account must be rejected when submitting alice's RADIUS State");
        assertEquals(RadiusConstants.ACCESS_ACCEPT,
                sendRadius("CORP\\alice", otpForStep(aliceSecret, step), aliceState).getCode(),
                "Canonical alice challenge State must survive rejected mismatch from alice@partner.example");

        // 3. Rotating OTP secret and deleting alice@partner.example must not invalidate alice's pending sessions
        assertTrue(postMfaPreAuth("alice", Integer.parseInt(otpForStep(aliceSecret, step + 1))));
        byte[] aliceState2 = obtainChallengeState("alice");
        assertEquals(1, challengeRepository.count());

        mockMvc.perform(post("/v1/api/otp/generate/alice@partner.example"))
                .andExpect(status().isOk());
        mockMvc.perform(delete("/v1/api/users/" + partnerId))
                .andExpect(status().is2xxSuccessful());

        assertTrue(mfaPreAuthService.hasActiveApproval("alice"),
                "Rotating secret or deleting alice@partner.example must preserve alice's MFA approval");
        assertEquals(1, challengeRepository.count(),
                "Rotating secret or deleting alice@partner.example must preserve alice's pending RADIUS challenge");
        assertEquals(RadiusConstants.ACCESS_ACCEPT, sendRadius("alice", null, null).getCode());
    }

    @Test
    void webMfaFormLockoutPropagatesAcrossAllChannelsRespectsMfaWindowAndResetsOnCrossChannelSuccess() throws Exception {
        configurePolicy(5, 2, 1, 300, 60);
        long step = stableCurrentStep();
        String secret = distinctSecret(step);
        User mfaWebUser = createUser("mfa-web", PASSWORD, secret);
        String wrongOtp = wrongOtpForStep(secret, step);

        assertFalse(postWebMfaForm("CORP\\mfa-web", wrongOtp));
        assertFalse(postWebMfaForm("CORP\\mfa-web", wrongOtp));

        // Sleep past lockoutSeconds (1s) while staying inside mfaLockoutWindowSeconds (60s)
        Thread.sleep(1300L);
        long postSleepStep = stableCurrentStep();
        String validOtp = otpForStep(secret, postSleepStep);
        String validOcra = ocraService.generateOcra(secret, "11223344");

        assertFalse(postWebMfaForm("mfa-web", validOtp),
                "Web /mfa form must remain locked during mfaLockoutWindowSeconds");
        assertFalse(postMfaPreAuth("mfa-web", Integer.parseInt(validOtp)),
                "REST MFA Pre-Auth must remain locked during mfaLockoutWindowSeconds");
        assertFalse(postWebLogin("mfa-web", PASSWORD, validOtp).path("authenticated").asBoolean(),
                "Web Login must remain locked past lockoutSeconds when MFA pre-auth triggered mfaLockoutWindowSeconds");
        assertFalse(postValidateOtp(mfaWebUser.getUsername(), Integer.parseInt(validOtp)),
                "/v1/api/otp/validate must remain locked during mfaLockoutWindowSeconds");
        assertFalse(postValidateOcra(mfaWebUser.getUsername(), "11223344", validOcra),
                "/v1/api/otp/validate-ocra must remain locked during mfaLockoutWindowSeconds");
        assertEquals(RadiusConstants.ACCESS_REJECT, sendRadius("mfa-web", PASSWORD, null).getCode(),
                "In-band RADIUS must remain locked during mfaLockoutWindowSeconds");
        assertEquals(RadiusConstants.ACCESS_REJECT, sendRadius("mfa-web", null, null).getCode(),
                "Out-of-band RADIUS must remain locked during mfaLockoutWindowSeconds");

        // Unknown realm-qualified /mfa submissions must not pre-lock a later-provisioned canonical account
        assertFalse(postWebMfaForm("unborn@partner.example", wrongOtp));
        assertFalse(postWebMfaForm("unborn@partner.example", wrongOtp));
        long unbornStep = stableCurrentStep();
        String unbornSecret = distinctSecret(unbornStep);
        createUser("unborn", PASSWORD, unbornSecret);
        assertTrue(postWebMfaForm("unborn", otpForStep(unbornSecret, unbornStep)),
                "Prior failures on unknown unborn@partner.example must not lock newly created canonical account");

        // Cross-channel Web Login success must reset accumulated /mfa web-form failures
        configurePolicy(4, 4, 120, 300, 300);
        long resetStep = stableCurrentStep();
        String resetSecret = distinctSecret(resetStep);
        createUser("mfa-reset", PASSWORD, resetSecret);
        String wrongResetOtp = wrongOtpForStep(resetSecret, resetStep);

        for (int i = 0; i < 3; i++) {
            assertFalse(postWebMfaForm("mfa-reset", wrongResetOtp));
        }
        assertTrue(postWebLogin("mfa-reset", PASSWORD, otpForStep(resetSecret, resetStep))
                .path("authenticated").asBoolean());
        for (int i = 0; i < 3; i++) {
            assertFalse(postWebMfaForm("mfa-reset", wrongResetOtp));
        }
        assertTrue(postWebMfaForm("mfa-reset", otpForStep(resetSecret, resetStep + 1)),
                "Web Login success must clear /mfa form failure counter so 3 subsequent failures do not lock out at threshold 4");
    }

    @Test
    void expiredRadiusChallengesDoNotExhaustPendingCapacityAndNullClientAddressIsHandledSafely() throws Exception {
        SecurityPolicy policy = policyRepository.findByName(SecurityPolicy.DEFAULT_NAME).orElseThrow();
        policy.setChallengeMaxPending(2);
        policy.setChallengeTtlSeconds(1);
        policyRepository.saveAndFlush(policy);

        long step = stableCurrentStep();
        String capSecret = distinctSecret(step);
        createUser("cap-user", PASSWORD, capSecret);

        obtainChallengeState("cap-user");
        obtainChallengeState("cap-user");
        assertEquals(RadiusConstants.ACCESS_REJECT, sendRadius("cap-user", PASSWORD, null).getCode(),
                "Active pending challenges at challengeMaxPending must reject additional challenges");

        Thread.sleep(1300L);
        long postExpireStep = stableCurrentStep();
        obtainChallengeState("cap-user");
        byte[] capState2 = obtainChallengeState("cap-user");
        assertEquals(RadiusConstants.ACCESS_ACCEPT,
                sendRadius("cap-user", otpForStep(capSecret, postExpireStep), capState2).getCode(),
                "Expired challenges must not count against challengeMaxPending capacity");

        policy = policyRepository.findByName(SecurityPolicy.DEFAULT_NAME).orElseThrow();
        policy.setChallengeMaxPending(10_000);
        policy.setChallengeTtlSeconds(60);
        policyRepository.saveAndFlush(policy);

        // Null InetAddress must not raise NullPointerException in either resolve or handle paths
        byte[] rawReq = buildSignedRadiusPacket("cap-user", PASSWORD, null);
        RadiusPacket decoded = RadiusPacket.decode(rawReq, rawReq.length);
        assertTrue(radiusHandler.handle(decoded, null).isEmpty(),
                "Unauthorized lookup with null client address must silently drop without NPE");

        RadiusClientRegistry.ResolvedClient resolvedClient = new RadiusClientRegistry.ResolvedClient(
                1L, "null-addr-client", RADIUS_SECRET.getBytes(StandardCharsets.UTF_8));
        byte[] challengeBytes = radiusHandler.handle(decoded, null, resolvedClient).orElseThrow();
        RadiusPacket challengePacket = RadiusPacket.decode(challengeBytes, challengeBytes.length);
        assertEquals(RadiusConstants.ACCESS_CHALLENGE, challengePacket.getCode());
        byte[] nullAddrState = challengePacket.getAttribute(RadiusConstants.ATTR_STATE).orElseThrow().getValue();

        long nullStep = stableCurrentStep();
        byte[] rawStep2 = buildSignedRadiusPacket("cap-user", otpForStep(capSecret, nullStep + 1), nullAddrState);
        RadiusPacket decodedStep2 = RadiusPacket.decode(rawStep2, rawStep2.length);
        byte[] acceptBytes = radiusHandler.handle(decodedStep2, null, resolvedClient).orElseThrow();
        RadiusPacket acceptPacket = RadiusPacket.decode(acceptBytes, acceptBytes.length);
        assertEquals(RadiusConstants.ACCESS_ACCEPT, acceptPacket.getCode());
    }

    private byte[] buildSignedRadiusPacket(String userName, String password, byte[] state) {
        byte[] secretBytes = RADIUS_SECRET.getBytes(StandardCharsets.UTF_8);
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
        return RadiusCrypto.buildRequest(RadiusConstants.ACCESS_REQUEST, id, authenticator, attributes, secretBytes, true);
    }

    static class MockLdapServer implements AutoCloseable {
        private final ServerSocket serverSocket;
        private final Thread thread;
        private volatile boolean running = true;
        private final String validUser;
        private final String validPassword;

        MockLdapServer(String validUser, String validPassword) throws IOException {
            this.validUser = validUser;
            this.validPassword = validPassword;
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
                    int seqLen = readLength(in);
                    byte[] seqBytes = readBytes(in, seqLen);
                    ByteArrayInputStream bin = new ByteArrayInputStream(seqBytes);

                    bin.read();
                    int idLen = readLength(bin);
                    byte[] idBytes = readBytes(bin, idLen);
                    int messageId = 0;
                    for (byte b : idBytes) {
                        messageId = (messageId << 8) | (b & 0xFF);
                    }

                    int opTag = bin.read();
                    int opLen = readLength(bin);
                    byte[] opBytes = readBytes(bin, opLen);
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
                                || (("uid=" + validUser + ",ou=users,dc=corp,dc=org").equalsIgnoreCase(bindDn)
                                && validPassword.equals(pass));
                        sendBindResponse(out, messageId, ok ? 0 : 49);
                    } else if (opTag == 0x63) {
                        opIn.read();
                        readBytes(opIn, readLength(opIn));
                        for (int i = 0; i < 5; i++) {
                            opIn.read();
                            readBytes(opIn, readLength(opIn));
                        }
                        String filterStr = new String(readRemaining(opIn), StandardCharsets.UTF_8);
                        if (filterStr.toLowerCase(Locale.ROOT).contains(validUser.toLowerCase(Locale.ROOT))) {
                            sendSearchResultEntry(out, messageId,
                                    "uid=" + validUser + ",ou=users,dc=corp,dc=org", validUser);
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
