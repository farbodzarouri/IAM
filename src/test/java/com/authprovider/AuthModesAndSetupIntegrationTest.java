package com.authprovider;

import static com.authprovider.OAuthTestSupport.bearer;
import com.authprovider.config.DatabaseConfigurationBootstrap;
import com.authprovider.entity.Admin;
import com.authprovider.entity.AuthAuditLog;
import com.authprovider.entity.AuthMode;
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
import com.authprovider.repository.AuthAuditLogRepository;
import com.authprovider.repository.AuthFailureRecordRepository;
import com.authprovider.repository.LdapDirectoryRepository;
import com.authprovider.repository.OcraChallengeUseRepository;
import com.authprovider.repository.OtpReplayStateRepository;
import com.authprovider.repository.OtpTokenRepository;
import com.authprovider.repository.PersonRepository;
import com.authprovider.repository.RadiusChallengeSessionRepository;
import com.authprovider.repository.RadiusClientRepository;
import com.authprovider.repository.SecurityPolicyRepository;
import com.authprovider.repository.UserRepository;
import com.authprovider.service.AccountLockoutService;
import com.authprovider.service.OcraService;
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
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(properties = {
        "radius.port=0",
        "radius.bind-address=127.0.0.1",
        "iam.bootstrap.radius.shared-secret=mode-secret",
        "iam.bootstrap.policy.max-failures=3",
        "iam.bootstrap.policy.lockout-seconds=120",
        "iam.bootstrap.policy.challenge-ttl-seconds=60",
        "iam.bootstrap.policy.mfa-approval-ttl-seconds=60"
})
@AutoConfigureMockMvc
class AuthModesAndSetupIntegrationTest {

    private static final String RADIUS_SECRET = "mode-secret";
    private static final String USER_PASS = "UserPass!123";
    private static final String ADMIN_PASS = "AdminPass!456";
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base32 BASE32 = new Base32();
    private static final ObjectMapper JSON = new ObjectMapper();

    @Autowired private MockMvc mockMvc;
    @Autowired private DatabaseConfigurationBootstrap bootstrap;
    @Autowired private RadiusServer radiusServer;
    @Autowired private PersonService personService;
    @Autowired private AccountLockoutService lockoutService;
    @Autowired private SecretGenerator secretGenerator;
    @Autowired private OcraService ocraService;
    @Autowired private PersonRepository personRepository;
    @Autowired private OtpTokenRepository otpTokenRepository;
    @Autowired private AdminRepository adminRepository;
    @Autowired private UserRepository userRepository;
    @Autowired private com.authprovider.service.UserService userService;
    @Autowired private com.authprovider.TestClientAssignments assignments;
    @Autowired private AuthFailureRecordRepository failureRepository;
    @Autowired private RadiusChallengeSessionRepository challengeRepository;
    @Autowired private RadiusClientRepository radiusClientRepository;
    @Autowired private LdapDirectoryRepository ldapDirectoryRepository;
    @Autowired private OtpReplayStateRepository replayRepository;
    @Autowired private OcraChallengeUseRepository ocraRepository;
    @Autowired private AuthAuditLogRepository auditRepository;
    @Autowired private SecurityPolicyRepository policyRepository;
    @Autowired private Clock clock;

    private final AtomicInteger radiusIdSeq = new AtomicInteger(1);

    @BeforeEach
    void setUp() {
        cleanAll();
        bootstrap.seed();
        resetDefaultPolicy();
    }

    @AfterEach
    void tearDown() {
        cleanAll();
        bootstrap.seed();
        resetDefaultPolicy();
    }

    private void cleanAll() {
        challengeRepository.deleteAll();
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
        radiusClientRepository.findByName("default").ifPresent(c -> {
            c.setAuthMode(null);
            c.setActive(true);
            radiusClientRepository.saveAndFlush(c);
        });
        ldapDirectoryRepository.deleteAll();
        ldapDirectoryRepository.flush();
    }

    private void resetDefaultPolicy() {
        SecurityPolicy policy = policyRepository.findByName(SecurityPolicy.DEFAULT_NAME).orElseThrow();
        policy.setMaxFailures(3);
        policy.setLockoutSeconds(120);
        policy.setFailureWindowSeconds(300);
        policy.setChallengeTtlSeconds(60);
        policy.setChallengeMaxPending(10_000);
        policy.setMfaApprovalTtlSeconds(60);
        policy.setMfaMaxFailedAttempts(3);
        policy.setMfaLockoutWindowSeconds(300);
        policy.setOtpReuseWindowSeconds(120);
        policy.setRequireMessageAuthenticator(false);
        policy.setStripRealm(true);
        policy.setChallengePrompt("Enter your one-time passcode");
        policy.setMfaOutOfBandEnabled(true);
        policy.setDefaultAuthMode(AuthMode.PASSWORD_AND_OTP);
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
        if (password != null) {
            sb.append(",\"password\":\"").append(escapeJson(password)).append("\"");
        }
        if (otp != null) {
            sb.append(",\"otp\":\"").append(escapeJson(otp)).append("\"");
        }
        sb.append("}");
        MvcResult res = mockMvc.perform(post(endpoint).with(bearer())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(sb.toString()))
                .andReturn();
        return JSON.readTree(res.getResponse().getContentAsString());
    }

    private RadiusPacket sendRadius(String userName, String password, byte[] state) throws Exception {
        assignments.assignAll();
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
        byte[] packet = RadiusCrypto.buildRequest(
                RadiusConstants.ACCESS_REQUEST,
                radiusIdSeq.getAndIncrement() & 0xFF,
                authenticator,
                attributes,
                secretBytes,
                true);
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(3000);
            socket.send(new DatagramPacket(packet, packet.length, InetAddress.getLoopbackAddress(), radiusServer.getLocalPort()));
            byte[] buf = new byte[RadiusConstants.MAX_PACKET_LENGTH];
            DatagramPacket response = new DatagramPacket(buf, buf.length);
            socket.receive(response);
            return RadiusPacket.decode(response.getData(), response.getLength());
        }
    }

    private static String escapeJson(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    @Test
    void dayZeroSetupFlowWorksForLocalAdminAndAdminLdapAndLocksAfterCompletion() throws Exception {
        // Fresh empty DB: 0 admins and 0 admin LDAP directories -> setupRequired=true
        mockMvc.perform(get("/v1/api/setup/status"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.setupRequired").value(true));
        mockMvc.perform(get("/login"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/setup"));
        mockMvc.perform(get("/setup"))
                .andExpect(status().isOk());

        // Complete setup by creating first local admin
        mockMvc.perform(post("/v1/api/setup/admin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"rootadmin\",\"password\":\"" + ADMIN_PASS + "\",\"displayName\":\"Root Admin\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("rootadmin"));

        // Setup permanently locks once completed
        mockMvc.perform(get("/v1/api/setup/status"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.setupRequired").value(false));
        mockMvc.perform(get("/setup"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login"));
        mockMvc.perform(get("/login"))
                .andExpect(status().isOk());
        mockMvc.perform(post("/v1/api/setup/admin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"attacker\",\"password\":\"Hack!123\"}"))
                .andExpect(status().isForbidden());

        // Second fresh setup path: Admin LDAP directory with JIT auto-provisioning
        adminRepository.deleteAll();
        personRepository.deleteAll();
        mockMvc.perform(get("/v1/api/setup/status"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.setupRequired").value(true));

        try (PersonAdminAuthIntegrationTest.MockLdapServer adminLdap =
                     new PersonAdminAuthIntegrationTest.MockLdapServer("firstldapadmin", "FirstLdap!7")) {
            mockMvc.perform(post("/v1/api/setup/ldap")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"name\":\"corp-admin-ldap\",\"url\":\"ldap://127.0.0.1:" + adminLdap.getPort() + "\","
                                    + "\"baseDn\":\"dc=corp,dc=org\","
                                    + "\"userSearchFilter\":\"(&(objectClass=person)(|(uid={0})(sAMAccountName={0})))\","
                                    + "\"autoProvision\":true,\"fallbackToLocal\":false}"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.adminEnabled").value(true));

            mockMvc.perform(get("/v1/api/setup/status"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.setupRequired").value(false));

            JsonNode enroll = postLogin("/v1/api/admin/auth/login", "firstldapadmin", "FirstLdap!7", null);
            assertEquals("ENROLLMENT_REQUIRED", enroll.path("status").asText());
            assertEquals("LDAP", enroll.path("authenticationSource").asText());
        }
    }

    @Test
    @WithMockUser
    void globalExceptionHandlerReturnsProperHttpStatuses() throws Exception {
        mockMvc.perform(post("/v1/api/persons/tokens/999999/rotate"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").exists());

        mockMvc.perform(get("/v1/api/users/999999"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").exists());

        mockMvc.perform(get("/v1/api/admins/999999"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").exists());

        mockMvc.perform(put("/v1/api/policies/current")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"maxFailures\":0,\"lockoutSeconds\":120,\"failureWindowSeconds\":300,"
                                + "\"challengeTtlSeconds\":60,\"challengeMaxPending\":10000,"
                                + "\"mfaApprovalTtlSeconds\":60,\"mfaMaxFailedAttempts\":3,"
                                + "\"mfaLockoutWindowSeconds\":300,\"otpReuseWindowSeconds\":120,"
                                + "\"challengePrompt\":\"Valid Prompt\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").exists());

        mockMvc.perform(post("/v1/api/users/create")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"dupuser\",\"password\":\"Secret!1\"}"))
                .andExpect(status().isOk());
        mockMvc.perform(post("/v1/api/users/create")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"DUPUSER\",\"password\":\"Secret!2\"}"))
                .andExpect(status().isConflict());
    }

    @Test
    void radiusSupportsInlineMfaOtpOnlyAndPasswordOnlyWithFactorAwareLockout() throws Exception {
        long step = stableCurrentStep();
        String sharedSecret = distinctSecret(step);
        Person person = personService.createPerson(Person.builder().displayName("Alice Multi").build());
        OtpToken token = personService.createToken(person.getId(), "yubikey", sharedSecret);

        User inlineUser = userRepository.save(User.builder()
                .username("alice")
                .password(USER_PASS)
                .person(person)
                .otpToken(token)
                .build());
        Admin linkedAdmin = adminRepository.save(Admin.builder()
                .username("alice.admin")
                .password(ADMIN_PASS)
                .person(person)
                .otpToken(token)
                .build());
        assignments.authMode(userRepository.save(User.builder()
                .username("svc-acct")
                .password(USER_PASS)
                .build()), AuthMode.PASSWORD_ONLY);
        User strictUser = assignments.authMode(userService.saveUser(User.builder()
                .username("strict-mfa")
                .password(USER_PASS)
                .otpToken(com.authprovider.TestUsers.token(sharedSecret))
                .build()), AuthMode.PASSWORD_AND_OTP);

        // 1. Service account with authMode=PASSWORD_ONLY gets single-factor Access-Accept without OTP
        assertEquals(RadiusConstants.ACCESS_ACCEPT, sendRadius("svc-acct", USER_PASS, null).getCode());

        // 2. PASSWORD_AND_OTP_INLINE NAS client accepts <password><6-digit-otp> in one packet
        RadiusClient defaultClient = radiusClientRepository.findByName("default").orElseThrow();
        defaultClient.setAuthMode(AuthMode.PASSWORD_AND_OTP_INLINE);
        radiusClientRepository.saveAndFlush(defaultClient);

        String otpMinus1 = otpForStep(sharedSecret, step - 1);
        assertEquals(RadiusConstants.ACCESS_ACCEPT, sendRadius("alice", USER_PASS + otpMinus1, null).getCode());
        assertEquals(RadiusConstants.ACCESS_REJECT, sendRadius("alice", USER_PASS + otpMinus1, null).getCode(),
                "Replayed inline OTP must be rejected");

        // Wrong password prefix in inline mode must NOT lock shared OtpToken / Admin
        lockoutService.recordSuccess(inlineUser.getId());
        for (int i = 0; i < 3; i++) {
            assertEquals(RadiusConstants.ACCESS_REJECT,
                    sendRadius("alice", "WrongPrefix!" + otpForStep(sharedSecret, step), null).getCode());
        }
        assertTrue(lockoutService.isLocked(inlineUser.getId()));
        assertFalse(lockoutService.isTokenLocked(token.getId()));
        assertTrue(postLogin("/v1/api/admin/auth/login", "alice.admin", ADMIN_PASS, otpForStep(sharedSecret, step))
                .path("authenticated").asBoolean());

        // Wrong OTP AFTER valid inline password DOES lock shared OtpToken / Admin (Option B)
        lockoutService.recordSuccess(inlineUser.getId());
        String wrongOtp = wrongOtpForStep(sharedSecret, step);
        for (int i = 0; i < 3; i++) {
            assertEquals(RadiusConstants.ACCESS_REJECT,
                    sendRadius("alice", USER_PASS + wrongOtp, null).getCode());
        }
        assertTrue(lockoutService.isTokenLocked(token.getId()));
        assertFalse(postLogin("/v1/api/admin/auth/login", "alice.admin", ADMIN_PASS, otpForStep(sharedSecret, step + 1))
                .path("authenticated").asBoolean());

        // Unlock for next check
        lockoutService.recordSuccess(inlineUser.getId());
        lockoutService.recordAdminSuccess(linkedAdmin.getId());
        failureRepository.deleteAll();

        // 3. OTP_ONLY client verifies 6-digit passcode directly without locking shared Admin token
        long step2 = stableCurrentStep();
        String otpOnlySecret = distinctSecret(step2);
        Person p2 = personService.createPerson(Person.builder().displayName("Bob Delegated").build());
        OtpToken tok2 = personService.createToken(p2.getId(), "bob-tok", otpOnlySecret);
        User bob = userRepository.save(User.builder()
                .username("bob")
                .password(USER_PASS)
                .person(p2)
                .otpToken(tok2)
                .build());
        adminRepository.save(Admin.builder()
                .username("bob.admin")
                .password(ADMIN_PASS)
                .person(p2)
                .otpToken(tok2)
                .build());

        defaultClient.setAuthMode(AuthMode.OTP_ONLY);
        radiusClientRepository.saveAndFlush(defaultClient);

        String bobOtp = otpForStep(otpOnlySecret, step2 - 1);
        assertEquals(RadiusConstants.ACCESS_ACCEPT, sendRadius("bob", bobOtp, null).getCode());
        assertEquals(RadiusConstants.ACCESS_REJECT, sendRadius("bob", bobOtp, null).getCode(),
                "Replayed OTP_ONLY code must be rejected");
        lockoutService.recordSuccess(bob.getId());
        String bobWrong = wrongOtpForStep(otpOnlySecret, step2);
        for (int i = 0; i < 3; i++) {
            assertEquals(RadiusConstants.ACCESS_REJECT, sendRadius("bob", bobWrong, null).getCode());
        }
        assertTrue(lockoutService.isLocked(bob.getId()));
        assertFalse(lockoutService.isTokenLocked(tok2.getId()),
                "OTP_ONLY failures must lock User only, not shared Admin OtpToken");
        assertTrue(postLogin("/v1/api/admin/auth/login", "bob.admin", ADMIN_PASS, otpForStep(otpOnlySecret, step2))
                .path("authenticated").asBoolean());

        // 4. Explicit User(PASSWORD_AND_OTP) is NOT downgraded even when client is PASSWORD_ONLY
        defaultClient.setAuthMode(AuthMode.PASSWORD_ONLY);
        radiusClientRepository.saveAndFlush(defaultClient);
        assertEquals(RadiusConstants.ACCESS_CHALLENGE, sendRadius(strictUser.getUsername(), USER_PASS, null).getCode());
    }

    @Test
    void restLoginModesAndUsernameBasedOtpApiWorkAndAudit() throws Exception {
        long step = stableCurrentStep();
        String secret = distinctSecret(step);
        Person person = personService.createPerson(Person.builder().displayName("Rest Modes").build());
        OtpToken token = personService.createToken(person.getId(), "rest-tok", secret);

        // PASSWORD_ONLY user logs in via REST without OTP or enrollment
        assignments.authMode(userRepository.save(User.builder()
                .username("rest-pw-only")
                .password(USER_PASS)
                .build()), AuthMode.PASSWORD_ONLY);
        JsonNode pwOnlyResp = postLogin("/v1/api/auth/login", "rest-pw-only", USER_PASS, null);
        assertTrue(pwOnlyResp.path("authenticated").asBoolean());
        assertEquals("AUTHENTICATED", pwOnlyResp.path("status").asText());

        // PASSWORD_AND_OTP_INLINE user logs in via REST with <pw><otp>
        assignments.authMode(userService.saveUser(User.builder()
                .username("rest-inline")
                .password(USER_PASS)
                .otpToken(com.authprovider.TestUsers.token(secret))
                .build()), AuthMode.PASSWORD_AND_OTP_INLINE);
        assertTrue(postLogin("/v1/api/auth/login", "rest-inline", USER_PASS + otpForStep(secret, step - 1), null)
                .path("authenticated").asBoolean());

        // OTP_ONLY unenrolled user cannot self-enroll without password
        assignments.authMode(userRepository.save(User.builder()
                .username("rest-otp-unenrolled")
                .build()), AuthMode.OTP_ONLY);
        JsonNode unenrolledResp = postLogin("/v1/api/auth/login", "rest-otp-unenrolled", null, otpForStep(secret, step));
        assertFalse(unenrolledResp.path("authenticated").asBoolean());
        assertEquals("NOT_PROVISIONED", unenrolledResp.path("status").asText());

        // OTP_ONLY enrolled user authenticates with OTP alone and locks only User on wrong attempts
        User otpOnlyUser = assignments.authMode(userRepository.save(User.builder()
                .username("rest-otp-only")
                .person(person)
                .otpToken(token)
                .build()), AuthMode.OTP_ONLY);
        adminRepository.save(Admin.builder()
                .username("rest.admin")
                .password(ADMIN_PASS)
                .person(person)
                .otpToken(token)
                .build());

        assertTrue(postLogin("/v1/api/auth/login", "rest-otp-only", null, otpForStep(secret, step))
                .path("authenticated").asBoolean());
        // Replay rejected
        assertFalse(postLogin("/v1/api/auth/login", "rest-otp-only", null, otpForStep(secret, step))
                .path("authenticated").asBoolean());

        // Username-based /v1/api/otp/validate & /validate-ocra return structured status & write OTP_VALIDATION audit log
        String otpPlus1 = otpForStep(secret, step + 1);
        MvcResult validRes = mockMvc.perform(post("/v1/api/otp/validate").with(bearer())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"CORP\\\\rest-otp-only\",\"otp\":\"" + otpPlus1 + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true))
                .andExpect(jsonPath("$.status").value("VALID"))
                .andExpect(jsonPath("$.username").value("rest-otp-only"))
                .andReturn();
        assertNotNull(validRes);

        String challenge = "24681357";
        String ocra = ocraService.generateOcra(secret, challenge);
        mockMvc.perform(post("/v1/api/otp/validate-ocra").with(bearer())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"rest-otp-only\",\"challenge\":\"" + challenge + "\",\"otp\":\"" + ocra + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true))
                .andExpect(jsonPath("$.status").value("VALID"));

        // Wrong OTP validation locks only User, leaving Admin accessible
        String wrong = wrongOtpForStep(secret, step);
        for (int i = 0; i < 3; i++) {
            mockMvc.perform(post("/v1/api/otp/validate").with(bearer())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"username\":\"rest-otp-only\",\"otp\":\"" + wrong + "\"}"))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.valid").value(false))
                    .andExpect(jsonPath("$.status").value("INVALID_OTP"));
        }
        mockMvc.perform(post("/v1/api/otp/validate").with(bearer())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"rest-otp-only\",\"otp\":\"" + otpPlus1 + "\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.status").value("LOCKED"));

        assertTrue(lockoutService.isLocked(otpOnlyUser.getId()));
        assertFalse(lockoutService.isTokenLocked(token.getId()));
        List<AuthAuditLog> otpAudits = auditRepository.findAll().stream()
                .filter(a -> a.getChannel() == AuthAuditLog.Channel.OTP_VALIDATION
                        && "rest-otp-only".equals(a.getUsername()))
                .toList();
        assertTrue(otpAudits.stream().anyMatch(a -> a.getOutcome() == AuthAuditLog.Outcome.SUCCESS && "VALID".equals(a.getReason())));
        assertTrue(otpAudits.stream().anyMatch(a -> a.getOutcome() == AuthAuditLog.Outcome.LOCKED && "LOCKED_OUT".equals(a.getReason())));
    }

    @Test
    @WithMockUser
    void dtoContractsPreserveDisabledStatusOmitSecretsAndLeaveZeroOrphanPersons() throws Exception {
        long baselinePersons = personRepository.count();

        // Failing User creation with invalid token must leave 0 new Person rows
        mockMvc.perform(post("/v1/api/users/create")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"orphan-check\",\"password\":\"Secret!1\",\"otpTokenId\":999999}"))
                .andExpect(status().isBadRequest());
        assertEquals(baselinePersons, personRepository.count());

        // Failing Admin creation with invalid token must leave 0 new Person rows
        mockMvc.perform(post("/v1/api/admins/create")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"orphan-admin\",\"password\":\"Secret!2\",\"otpTokenId\":999999}"))
                .andExpect(status().isBadRequest());
        assertEquals(baselinePersons, personRepository.count());

        // Create Person + Token + User, then test credential-separation failure via token-inferred Person leaves 0 orphans
        Person owner = personService.createPerson(Person.builder().displayName("Owner").build());
        OtpToken ownerToken = personService.createToken(owner.getId(), "tok", "JBSWY3DPEHPK3PXP");

        MvcResult createdUserRes = mockMvc.perform(post("/v1/api/users/create")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"dto-user\",\"password\":\"" + USER_PASS
                                + "\",\"secret\":\"JBSWY3DPEHPK3PXP\",\"personId\":" + owner.getId()
                                + ",\"otpTokenId\":" + ownerToken.getId() + ",\"enabled\":false}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("dto-user"))
                .andExpect(jsonPath("$.enabled").value(false))
                .andExpect(jsonPath("$.personId").value(owner.getId()))
                .andExpect(jsonPath("$.otpTokenId").value(ownerToken.getId()))
                .andExpect(jsonPath("$.password").doesNotExist())
                .andExpect(jsonPath("$.secret").doesNotExist())
                .andReturn();
        long userId = JSON.readTree(createdUserRes.getResponse().getContentAsString()).path("id").asLong();

        // PUT /v1/api/users/{id} omitting "enabled" preserves enabled=false
        mockMvc.perform(put("/v1/api/users/" + userId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"dto-user-renamed\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("dto-user-renamed"))
                .andExpect(jsonPath("$.enabled").value(false))
                .andExpect(jsonPath("$.password").doesNotExist())
                .andExpect(jsonPath("$.secret").doesNotExist());
        assertFalse(userRepository.findById(userId).orElseThrow().isEnabled());

        // Admin creation reusing user's password via inferred Person fails without creating orphan Person
        long personsAfterOwner = personRepository.count();
        mockMvc.perform(post("/v1/api/admins/create")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"dto-admin\",\"password\":\"" + USER_PASS
                                + "\",\"otpTokenId\":" + ownerToken.getId() + "}"))
                .andExpect(status().isBadRequest());
        assertEquals(personsAfterOwner, personRepository.count());

        // Valid disabled Admin creation omits password and preserves enabled=false on PUT without "enabled"
        MvcResult createdAdminRes = mockMvc.perform(post("/v1/api/admins/create")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"dto-admin\",\"password\":\"" + ADMIN_PASS
                                + "\",\"personId\":" + owner.getId()
                                + ",\"otpTokenId\":" + ownerToken.getId() + ",\"enabled\":false}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("dto-admin"))
                .andExpect(jsonPath("$.enabled").value(false))
                .andExpect(jsonPath("$.personId").value(owner.getId()))
                .andExpect(jsonPath("$.otpTokenId").value(ownerToken.getId()))
                .andExpect(jsonPath("$.password").doesNotExist())
                .andExpect(jsonPath("$.secret").doesNotExist())
                .andReturn();
        long adminId = JSON.readTree(createdAdminRes.getResponse().getContentAsString()).path("id").asLong();

        mockMvc.perform(put("/v1/api/admins/" + adminId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"dto-admin-renamed\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("dto-admin-renamed"))
                .andExpect(jsonPath("$.enabled").value(false))
                .andExpect(jsonPath("$.password").doesNotExist());
        assertFalse(adminRepository.findById(adminId).orElseThrow().isEnabled());
    }
}
