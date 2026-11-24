package com.authprovider;

import com.authprovider.config.DatabaseConfigurationBootstrap;
import com.authprovider.entity.Admin;
import com.authprovider.entity.AuthMode;
import com.authprovider.entity.ClientScope;
import com.authprovider.entity.OAuthClient;
import com.authprovider.entity.OtpToken;
import com.authprovider.entity.Person;
import com.authprovider.entity.RadiusClient;
import com.authprovider.entity.SecurityPolicy;
import com.authprovider.entity.User;
import com.authprovider.oauth2.AccessTokenService;
import com.authprovider.radius.RadiusAttribute;
import com.authprovider.radius.RadiusConstants;
import com.authprovider.radius.RadiusCrypto;
import com.authprovider.radius.RadiusPacket;
import com.authprovider.radius.RadiusServer;
import com.authprovider.repository.AdminRepository;
import com.authprovider.repository.AuthFailureRecordRepository;
import com.authprovider.repository.MfaApprovalRepository;
import com.authprovider.repository.OAuthClientRepository;
import com.authprovider.repository.OcraChallengeUseRepository;
import com.authprovider.repository.OtpReplayStateRepository;
import com.authprovider.repository.OtpTokenRepository;
import com.authprovider.repository.PersonRepository;
import com.authprovider.repository.RadiusChallengeSessionRepository;
import com.authprovider.repository.RadiusClientRepository;
import com.authprovider.repository.SecurityPolicyRepository;
import com.authprovider.repository.UserRepository;
import com.authprovider.service.AdminService;
import com.authprovider.service.ClientService;
import com.authprovider.service.OcraService;
import com.authprovider.service.RadiusClientService;
import com.authprovider.service.SecretGenerator;
import com.authprovider.service.UserService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.binary.Base32;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(properties = {
        "radius.port=0",
        "radius.bind-address=127.0.0.1",
        "iam.bootstrap.radius.shared-secret=reg-rad-secret",
        "iam.bootstrap.admin.username=reg-boot-admin",
        "iam.bootstrap.admin.password=RegBootAdm!123_ZxQvBnM9",
        "iam.bootstrap.policy.max-failures=5",
        "iam.bootstrap.policy.lockout-seconds=120",
        "iam.bootstrap.policy.mfa-approval-ttl-seconds=60",
        "iam.bootstrap.policy.challenge-ttl-seconds=60"
})
@AutoConfigureMockMvc
class PersonRegistrationIntegrationTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Base32 BASE32 = new Base32();
    private static final String RADIUS_SECRET = "reg-rad-secret";
    private static final String USER_PASS = "RegUser!Pass123";
    private static final SecureRandom RANDOM = new SecureRandom();

    @Autowired private MockMvc mockMvc;
    @Autowired private RadiusServer radiusServer;
    @Autowired private DatabaseConfigurationBootstrap bootstrap;
    @Autowired private UserService userService;
    @Autowired private AdminService adminService;
    @Autowired private ClientService clientService;
    @Autowired private RadiusClientService radiusClientService;
    @Autowired private AccessTokenService accessTokenService;
    @Autowired private OcraService ocraService;
    @Autowired private SecretGenerator secretGenerator;
    @Autowired private PersonRepository personRepository;
    @Autowired private OtpTokenRepository otpTokenRepository;
    @Autowired private UserRepository userRepository;
    @Autowired private AdminRepository adminRepository;
    @Autowired private OAuthClientRepository oauthClientRepository;
    @Autowired private RadiusClientRepository radiusClientRepository;
    @Autowired private SecurityPolicyRepository policyRepository;
    @Autowired private RadiusChallengeSessionRepository challengeRepository;
    @Autowired private MfaApprovalRepository approvalRepository;
    @Autowired private AuthFailureRecordRepository failureRepository;
    @Autowired private OtpReplayStateRepository replayRepository;
    @Autowired private OcraChallengeUseRepository ocraRepository;
    @Autowired private Clock clock;

    private final AtomicInteger radiusIdSeq = new AtomicInteger(1);

    @BeforeEach
    void setUp() {
        cleanAll();
        bootstrap.seed();
        resetPolicy();
    }

    @AfterEach
    void tearDown() {
        cleanAll();
        bootstrap.seed();
        resetPolicy();
    }

    private void cleanAll() {
        challengeRepository.deleteAll();
        approvalRepository.deleteAll();
        failureRepository.deleteAll();
        replayRepository.deleteAll();
        ocraRepository.deleteAll();
        for (User u : userRepository.findAll()) {
            userService.deleteUser(u.getId());
        }
        for (Admin a : adminRepository.findAll()) {
            adminService.deleteAdmin(a.getId());
        }
        otpTokenRepository.deleteAll();
        personRepository.deleteAll();
        for (OAuthClient oc : oauthClientRepository.findAll()) {
            clientService.deleteClient(oc.getId());
        }
        radiusClientRepository.findAll().stream()
                .filter(c -> !c.getName().startsWith("default"))
                .forEach(c -> radiusClientService.deleteClient(c.getId()));
    }

    private void resetPolicy() {
        SecurityPolicy policy = policyRepository.findByName(SecurityPolicy.DEFAULT_NAME).orElseThrow();
        policy.setDefaultAuthMode(AuthMode.PASSWORD_AND_OTP);
        policy.setMaxFailures(5);
        policy.setMfaMaxFailedAttempts(5);
        policy.setLockoutSeconds(120);
        policy.setRequireMessageAuthenticator(false);
        policy.setStripRealm(true);
        policy.setMfaOutOfBandEnabled(true);
        policyRepository.saveAndFlush(policy);
    }

    private static RequestPostProcessor adminUser() {
        return SecurityMockMvcRequestPostProcessors.user("reg-boot-admin").roles("ADMIN");
    }

    private static RequestPostProcessor plainUser() {
        return SecurityMockMvcRequestPostProcessors.user("plain-operator").roles("USER");
    }

    private RequestPostProcessor bearerFor(OAuthClient client) {
        String token = accessTokenService.issue(client, EnumSet.allOf(ClientScope.class)).value();
        return request -> {
            request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + token);
            return request;
        };
    }

    private OAuthClient createOAuthClient(String prefix, AuthMode authMode) {
        var created = clientService.createClient(com.authprovider.dto.ClientRequest.builder()
                .clientId(prefix + "-" + UUID.randomUUID().toString().substring(0, 8))
                .name(prefix)
                .enabled(true)
                .blocked(false)
                .authMode(authMode)
                .scopes(List.of("auth:login", "otp:validate", "mfa:preauth"))
                .build());
        return oauthClientRepository.findById(created.getId()).orElseThrow();
    }

    private RadiusClient defaultRadiusClient() {
        return radiusClientRepository.findAll().stream()
                .filter(c -> "default".equals(c.getName()))
                .findFirst()
                .orElseThrow();
    }

    private long stableCurrentStep() throws InterruptedException {
        while (clock.millis() % 30_000L > 22_000L) {
            Thread.sleep(200);
        }
        return clock.millis() / 30_000L;
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
            throw new IllegalStateException("Failed to compute TOTP", e);
        }
    }

    private RadiusPacket sendRadius(String userName, String password, byte[] state) throws Exception {
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
        byte[] reqBytes = RadiusCrypto.buildRequest(
                RadiusConstants.ACCESS_REQUEST, radiusIdSeq.getAndIncrement() & 0xFF,
                authenticator, attributes, secretBytes, true);
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(3000);
            socket.send(new DatagramPacket(reqBytes, reqBytes.length,
                    InetAddress.getByName("127.0.0.1"), radiusServer.getLocalPort()));
            byte[] buf = new byte[RadiusConstants.MAX_PACKET_LENGTH];
            DatagramPacket in = new DatagramPacket(buf, buf.length);
            socket.receive(in);
            return RadiusPacket.decode(in.getData(), in.getLength());
        }
    }

    // -------------------------------------------------------------------------
    // 1. Rich Person profile CRUD, auto-derived displayName & delete protection
    // -------------------------------------------------------------------------
    @Test
    void richPersonCrudDerivesDisplayNameNormalizesFieldsAndEnforcesDeleteProtection() throws Exception {
        Map<String, Object> createPayload = new LinkedHashMap<>();
        createPayload.put("firstName", "  Sara  ");
        createPayload.put("lastName", " Karimi ");
        createPayload.put("email", "Sara.Karimi@Example.COM");
        createPayload.put("mobile", "+98 (912) 345-6789");
        createPayload.put("nationalCode", "ir-0012345");

        MvcResult createdRes = mockMvc.perform(post("/v1/api/persons/create").with(adminUser())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(createPayload)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.firstName").value("Sara"))
                .andExpect(jsonPath("$.lastName").value("Karimi"))
                .andExpect(jsonPath("$.displayName").value("Sara Karimi"))
                .andExpect(jsonPath("$.email").value("sara.karimi@example.com"))
                .andExpect(jsonPath("$.mobile").value("+989123456789"))
                .andExpect(jsonPath("$.nationalCode").value("IR-0012345"))
                .andExpect(jsonPath("$.enabled").value(true))
                .andReturn();
        long personId = JSON.readTree(createdRes.getResponse().getContentAsString()).get("id").asLong();

        mockMvc.perform(get("/v1/api/persons/" + personId).with(adminUser()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.displayName").value("Sara Karimi"))
                .andExpect(jsonPath("$.nationalCode").value("IR-0012345"));

        // Partial PUT updating firstName re-derives displayName when displayName matched previous derived name
        mockMvc.perform(put("/v1/api/persons/" + personId).with(adminUser())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"firstName\":\"Zahra\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.firstName").value("Zahra"))
                .andExpect(jsonPath("$.lastName").value("Karimi"))
                .andExpect(jsonPath("$.displayName").value("Zahra Karimi"))
                .andExpect(jsonPath("$.email").value("sara.karimi@example.com"))
                .andExpect(jsonPath("$.enabled").value(true));

        // Custom displayName is preserved across subsequent firstName updates
        mockMvc.perform(put("/v1/api/persons/" + personId).with(adminUser())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"displayName\":\"Dr. Karimi\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.displayName").value("Dr. Karimi"));

        mockMvc.perform(put("/v1/api/persons/" + personId).with(adminUser())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"firstName\":\"Mina\",\"mobile\":\"\",\"enabled\":false}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.firstName").value("Mina"))
                .andExpect(jsonPath("$.displayName").value("Dr. Karimi"))
                .andExpect(jsonPath("$.mobile").doesNotExist())
                .andExpect(jsonPath("$.enabled").value(false));

        // Omitting enabled on PUT preserves enabled=false
        mockMvc.perform(put("/v1/api/persons/" + personId).with(adminUser())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"lastName\":\"Noori\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.enabled").value(false));

        // Attach token + user -> DELETE person must return 409 Conflict until unlinked
        mockMvc.perform(post("/v1/api/persons/" + personId + "/tokens").with(adminUser())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"label\":\"main-key\"}"))
                .andExpect(status().isOk());
        MvcResult uRes = mockMvc.perform(post("/v1/api/users/create").with(adminUser())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"sara-linked\",\"password\":\"" + USER_PASS
                                + "\",\"personId\":" + personId + "}"))
                .andExpect(status().isOk())
                .andReturn();
        long userId = JSON.readTree(uRes.getResponse().getContentAsString()).get("id").asLong();

        mockMvc.perform(delete("/v1/api/persons/" + personId).with(adminUser()))
                .andExpect(status().isConflict());

        mockMvc.perform(delete("/v1/api/users/" + userId).with(adminUser()))
                .andExpect(status().isOk());
        mockMvc.perform(delete("/v1/api/persons/" + personId).with(adminUser()))
                .andExpect(status().isOk());
        mockMvc.perform(get("/v1/api/persons/" + personId).with(adminUser()))
                .andExpect(status().isNotFound());
        assertTrue(otpTokenRepository.findByPersonId(personId).isEmpty());
    }

    // -------------------------------------------------------------------------
    // 2. Format validation (400) & uniqueness (409 + concurrency + multiple nulls)
    // -------------------------------------------------------------------------
    @Test
    void personValidationAndUniquenessRejectsInvalidFormatsAndConcurrentDuplicates() throws Exception {
        // Missing displayName AND missing firstName/lastName -> 400
        mockMvc.perform(post("/v1/api/persons/create").with(adminUser())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"nobody@example.com\"}"))
                .andExpect(status().isBadRequest());

        // Invalid formats -> 400
        mockMvc.perform(post("/v1/api/persons/create").with(adminUser())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"displayName\":\"Bad Email\",\"email\":\"not-an-email\"}"))
                .andExpect(status().isBadRequest());
        mockMvc.perform(post("/v1/api/persons/create").with(adminUser())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"displayName\":\"Bad Mobile\",\"mobile\":\"abc-123\"}"))
                .andExpect(status().isBadRequest());
        mockMvc.perform(post("/v1/api/persons/create").with(adminUser())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"displayName\":\"Bad Code\",\"nationalCode\":\"12\"}"))
                .andExpect(status().isBadRequest());

        // Multiple Persons with null optional unique columns succeed without constraint errors
        mockMvc.perform(post("/v1/api/persons/create").with(adminUser())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"displayName\":\"Stub One\"}"))
                .andExpect(status().isOk());
        mockMvc.perform(post("/v1/api/persons/create").with(adminUser())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"displayName\":\"Stub Two\"}"))
                .andExpect(status().isOk());

        // Uniqueness across email (case-insensitive), mobile (normalized), nationalCode (case-insensitive)
        mockMvc.perform(post("/v1/api/persons/create").with(adminUser())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"firstName\":\"Reza\",\"lastName\":\"Moradi\","
                                + "\"email\":\"reza@example.com\",\"mobile\":\"+989120001122\",\"nationalCode\":\"NC-9001\"}"))
                .andExpect(status().isOk());

        mockMvc.perform(post("/v1/api/persons/create").with(adminUser())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"displayName\":\"Dup Email\",\"email\":\"REZA@EXAMPLE.COM\"}"))
                .andExpect(status().isConflict());
        mockMvc.perform(post("/v1/api/persons/create").with(adminUser())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"displayName\":\"Dup Mobile\",\"mobile\":\"+98 912-000-1122\"}"))
                .andExpect(status().isConflict());
        mockMvc.perform(post("/v1/api/persons/create").with(adminUser())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"displayName\":\"Dup Code\",\"nationalCode\":\"nc-9001\"}"))
                .andExpect(status().isConflict());

        // Concurrent creates racing on the same email must produce one 200 and 409s (never 500)
        int threads = 8;
        CountDownLatch gate = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        List<Future<Integer>> futures = new ArrayList<>();
        try {
            for (int i = 0; i < threads; i++) {
                int idx = i;
                futures.add(pool.submit(() -> {
                    gate.await(5, TimeUnit.SECONDS);
                    return mockMvc.perform(post("/v1/api/persons/create").with(adminUser())
                                    .contentType(MediaType.APPLICATION_JSON)
                                    .content("{\"displayName\":\"Racer " + idx + "\",\"email\":\"race@example.com\"}"))
                            .andReturn().getResponse().getStatus();
                }));
            }
            gate.countDown();
            int ok = 0;
            int conflict = 0;
            for (Future<Integer> f : futures) {
                int st = f.get(15, TimeUnit.SECONDS);
                if (st == 200) {
                    ok++;
                } else if (st == 409) {
                    conflict++;
                } else {
                    fail("Unexpected status during concurrent duplicate person create: " + st);
                }
            }
            assertEquals(1, ok);
            assertEquals(threads - 1, conflict);
        } finally {
            pool.shutdownNow();
        }
    }

    // -------------------------------------------------------------------------
    // 3. Unified atomic registration happy path + end-to-end REST & RADIUS auth
    // -------------------------------------------------------------------------
    @Test
    void unifiedRegistrationCreatesPersonTokenUserAndAssignmentsAtomicallyAndAuthenticatesEndToEnd() throws Exception {
        OAuthClient assignedOAuth = createOAuthClient("reg-oa-assigned", AuthMode.PASSWORD_AND_OTP);
        OAuthClient unassignedOAuth = createOAuthClient("reg-oa-other", AuthMode.PASSWORD_ONLY);
        RadiusClient defaultNas = defaultRadiusClient();

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("username", "ali.rezaei");
        body.put("password", USER_PASS);
        body.put("person", Map.of(
                "firstName", "Ali",
                "lastName", "Rezaei",
                "email", "Ali.Rezaei@Corp.Local",
                "mobile", "+98 912-111-2233",
                "nationalCode", "0088776655"));
        body.put("otpToken", Map.of("label", "yubikey-ali"));
        body.put("oauthClients", List.of(Map.of("clientId", assignedOAuth.getId(), "enabled", true)));
        body.put("radiusClients", List.of(Map.of("clientId", defaultNas.getId(), "enabled", true)));

        MvcResult regRes = mockMvc.perform(post("/v1/api/registration").with(adminUser())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(body)))
                .andExpect(status().isCreated())
                .andExpect(header().string(HttpHeaders.CACHE_CONTROL, org.hamcrest.Matchers.containsString("no-store")))
                .andExpect(jsonPath("$.person.displayName").value("Ali Rezaei"))
                .andExpect(jsonPath("$.person.email").value("ali.rezaei@corp.local"))
                .andExpect(jsonPath("$.person.mobile").value("+989121112233"))
                .andExpect(jsonPath("$.person.nationalCode").value("0088776655"))
                .andExpect(jsonPath("$.user.username").value("ali.rezaei"))
                .andExpect(jsonPath("$.user.password").doesNotExist())
                .andExpect(jsonPath("$.user.secret").doesNotExist())
                .andExpect(jsonPath("$.user.oauthClients[0].clientId").value(assignedOAuth.getId()))
                .andExpect(jsonPath("$.user.radiusClients[0].clientId").value(defaultNas.getId()))
                .andExpect(jsonPath("$.otpToken.label").value("yubikey-ali"))
                .andExpect(jsonPath("$.otpToken.secret").isNotEmpty())
                .andExpect(jsonPath("$.otpToken.otpAuthUri").isNotEmpty())
                .andExpect(jsonPath("$.otpToken.qrCode").isNotEmpty())
                .andReturn();

        JsonNode regJson = JSON.readTree(regRes.getResponse().getContentAsString());
        long personId = regJson.get("person").get("id").asLong();
        String secret = regJson.get("otpToken").get("secret").asText();

        long step = stableCurrentStep();
        String otpLogin = otpForStep(secret, step - 1);
        String otpValidate = otpForStep(secret, step);
        String otpRadius = otpForStep(secret, step + 1);

        // Immediately authenticate via assigned OAuth client
        mockMvc.perform(post("/v1/api/auth/login").with(bearerFor(assignedOAuth))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of(
                                "username", "ali.rezaei", "password", USER_PASS, "otp", otpLogin))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.authenticated").value(true));

        // Denied on unassigned OAuth client
        mockMvc.perform(post("/v1/api/auth/login").with(bearerFor(unassignedOAuth))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of(
                                "username", "ali.rezaei", "password", USER_PASS))))
                .andExpect(status().is4xxClientError());

        // Validate TOTP and OCRA via assigned OAuth client
        mockMvc.perform(post("/v1/api/otp/validate").with(bearerFor(assignedOAuth))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of("username", "ali.rezaei", "otp", otpValidate))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true));

        String challengeStr = "CHAL-" + UUID.randomUUID().toString().substring(0, 6);
        String ocraOtp = ocraService.generateOcra(secret, challengeStr);
        mockMvc.perform(post("/v1/api/otp/validate-ocra").with(bearerFor(assignedOAuth))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of(
                                "username", "ali.rezaei", "challenge", challengeStr, "otp", ocraOtp))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true));

        // Immediate UDP RADIUS 2-step authentication
        RadiusPacket ch = sendRadius("ali.rezaei", USER_PASS, null);
        assertEquals(RadiusConstants.ACCESS_CHALLENGE, ch.getCode());
        byte[] state = ch.getAttribute(RadiusConstants.ATTR_STATE).orElseThrow().getValue();
        RadiusPacket accept = sendRadius("ali.rezaei", otpRadius, state);
        assertEquals(RadiusConstants.ACCESS_ACCEPT, accept.getCode());

        // Person.enabled = false master kill-switch blocks both REST and RADIUS
        mockMvc.perform(put("/v1/api/persons/" + personId).with(adminUser())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"enabled\":false}"))
                .andExpect(status().isOk());

        mockMvc.perform(post("/v1/api/auth/login").with(bearerFor(assignedOAuth))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of(
                                "username", "ali.rezaei", "password", USER_PASS))))
                .andExpect(status().is4xxClientError())
                .andExpect(jsonPath("$.authenticated").value(false));
        assertEquals(RadiusConstants.ACCESS_REJECT, sendRadius("ali.rezaei", USER_PASS, null).getCode());
    }

    // -------------------------------------------------------------------------
    // 4. Linking existing Person + existing OtpToken omits secret re-exposure
    // -------------------------------------------------------------------------
    @Test
    void unifiedRegistrationViaUsersRegisterLinksExistingPersonAndTokenWithoutLeakingSecret() throws Exception {
        OAuthClient oauth = createOAuthClient("reg-link-oa", AuthMode.PASSWORD_AND_OTP);
        String existingSecret = secretGenerator.generateSecret();
        Person person = personRepository.saveAndFlush(Person.builder()
                .firstName("Neda")
                .lastName("Hosseini")
                .displayName("Neda Hosseini")
                .email("neda@example.com")
                .enabled(true)
                .build());
        OtpToken token = otpTokenRepository.saveAndFlush(OtpToken.builder()
                .person(person)
                .label("neda-shared-token")
                .secret(existingSecret)
                .enabled(true)
                .build());

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("username", "neda.vpn");
        body.put("password", USER_PASS);
        body.put("personId", person.getId());
        body.put("otpTokenId", token.getId());
        body.put("oauthClients", List.of(Map.of("clientId", oauth.getId(), "authMode", "OTP_ONLY")));

        mockMvc.perform(post("/v1/api/users/register").with(adminUser())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(body)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.person.id").value(person.getId()))
                .andExpect(jsonPath("$.user.personId").value(person.getId()))
                .andExpect(jsonPath("$.user.otpTokenId").value(token.getId()))
                .andExpect(jsonPath("$.user.oauthClients[0].authMode").value("OTP_ONLY"))
                .andExpect(jsonPath("$.otpToken.id").value(token.getId()))
                .andExpect(jsonPath("$.otpToken.secret").doesNotExist())
                .andExpect(jsonPath("$.otpToken.otpAuthUri").doesNotExist())
                .andExpect(jsonPath("$.otpToken.qrCode").doesNotExist());

        long step = stableCurrentStep();
        mockMvc.perform(post("/v1/api/auth/login").with(bearerFor(oauth))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of(
                                "username", "neda.vpn", "otp", otpForStep(existingSecret, step)))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.authenticated").value(true));
    }

    // -------------------------------------------------------------------------
    // 5. Complete atomic rollback on partial failures & concurrent duplicates
    // -------------------------------------------------------------------------
    @Test
    void unifiedRegistrationRollsBackCompletelyOnPartialFailuresAndConcurrentDuplicates() throws Exception {
        Person otherPerson = personRepository.saveAndFlush(Person.builder()
                .displayName("Other Owner").email("other@example.com").enabled(true).build());
        OtpToken otherToken = otpTokenRepository.saveAndFlush(OtpToken.builder()
                .person(otherPerson).label("other-tok").secret(secretGenerator.generateSecret()).enabled(true).build());

        Person alicePerson = personRepository.saveAndFlush(Person.builder()
                .displayName("Alice Existing").email("alice.existing@example.com").enabled(true).build());
        OtpToken aliceToken = otpTokenRepository.saveAndFlush(OtpToken.builder()
                .person(alicePerson).label("alice-tok").secret(secretGenerator.generateSecret()).enabled(true).build());
        adminService.createAdmin(com.authprovider.dto.AdminRequest.builder()
                .username("alice.admin")
                .password("AdminDistinct!999")
                .personId(alicePerson.getId())
                .otpTokenId(aliceToken.getId())
                .enabled(true)
                .build());
        userService.createUser(com.authprovider.dto.UserRequest.builder()
                .username("existing-user")
                .password(USER_PASS)
                .personId(alicePerson.getId())
                .build());

        long basePersons = personRepository.count();
        long baseTokens = otpTokenRepository.count();
        long baseUsers = userRepository.count();

        // A. Invalid radius clientId -> 400 and ZERO new Person / OtpToken / User rows
        mockMvc.perform(post("/v1/api/registration").with(adminUser())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of(
                                "username", "fail-client",
                                "password", USER_PASS,
                                "person", Map.of("firstName", "Ghost", "lastName", "Client", "email", "ghost1@example.com"),
                                "provisionOtpToken", true,
                                "radiusClients", List.of(Map.of("clientId", 999999L))))))
                .andExpect(status().isBadRequest());
        assertCountsUnchanged(basePersons, baseTokens, baseUsers);

        // B. Duplicate username -> 409 and ZERO new Person / OtpToken rows
        mockMvc.perform(post("/v1/api/registration").with(adminUser())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of(
                                "username", "EXISTING-USER",
                                "password", USER_PASS,
                                "person", Map.of("displayName", "Dup User Owner", "email", "dupuser@example.com"),
                                "provisionOtpToken", true))))
                .andExpect(status().isConflict());
        assertCountsUnchanged(basePersons, baseTokens, baseUsers);

        // C. Duplicate person email -> 409 and ZERO new User / OtpToken rows
        mockMvc.perform(post("/v1/api/registration").with(adminUser())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of(
                                "username", "fresh-user",
                                "password", USER_PASS,
                                "person", Map.of("displayName", "Dup Email Owner", "email", "ALICE.EXISTING@EXAMPLE.COM"),
                                "provisionOtpToken", true))))
                .andExpect(status().isConflict());
        assertCountsUnchanged(basePersons, baseTokens, baseUsers);

        // D. Cross-person otpTokenId -> 400 and ZERO new User rows
        mockMvc.perform(post("/v1/api/registration").with(adminUser())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of(
                                "username", "wrong-token-user",
                                "password", USER_PASS,
                                "personId", alicePerson.getId(),
                                "otpTokenId", otherToken.getId()))))
                .andExpect(status().isBadRequest());
        assertCountsUnchanged(basePersons, baseTokens, baseUsers);

        // E. Mutual exclusivity validation -> 400
        mockMvc.perform(post("/v1/api/registration").with(adminUser())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of(
                                "username", "both-persons",
                                "password", USER_PASS,
                                "personId", alicePerson.getId(),
                                "person", Map.of("displayName", "Conflict")))))
                .andExpect(status().isBadRequest());
        mockMvc.perform(post("/v1/api/registration").with(adminUser())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"neither-person\",\"password\":\"Secret!123\"}"))
                .andExpect(status().isBadRequest());
        mockMvc.perform(post("/v1/api/registration").with(adminUser())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of(
                                "username", "both-tokens",
                                "password", USER_PASS,
                                "personId", alicePerson.getId(),
                                "otpTokenId", aliceToken.getId(),
                                "provisionOtpToken", true))))
                .andExpect(status().isBadRequest());
        assertCountsUnchanged(basePersons, baseTokens, baseUsers);

        // F. Admin credential separation enforced during registration -> 400
        mockMvc.perform(post("/v1/api/registration").with(adminUser())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of(
                                "username", "alice.admin",
                                "password", USER_PASS,
                                "personId", alicePerson.getId()))))
                .andExpect(status().isBadRequest());
        mockMvc.perform(post("/v1/api/registration").with(adminUser())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of(
                                "username", "alice.distinct",
                                "password", "AdminDistinct!999",
                                "personId", alicePerson.getId()))))
                .andExpect(status().isBadRequest());
        assertCountsUnchanged(basePersons, baseTokens, baseUsers);

        // G. Concurrent registrations with identical email -> one 201, rest 409 (zero 500s) and exact +1 DB rows
        int threads = 8;
        CountDownLatch gate = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        List<Future<Integer>> futures = new ArrayList<>();
        try {
            for (int i = 0; i < threads; i++) {
                int idx = i;
                futures.add(pool.submit(() -> {
                    gate.await(5, TimeUnit.SECONDS);
                    return mockMvc.perform(post("/v1/api/registration").with(adminUser())
                                    .contentType(MediaType.APPLICATION_JSON)
                                    .content(JSON.writeValueAsString(Map.of(
                                            "username", "race-user-" + idx,
                                            "password", USER_PASS,
                                            "person", Map.of(
                                                    "firstName", "Race",
                                                    "lastName", "User",
                                                    "email", "concurrent-reg@example.com"),
                                            "provisionOtpToken", true))))
                            .andReturn().getResponse().getStatus();
                }));
            }
            gate.countDown();
            int created = 0;
            int conflicts = 0;
            for (Future<Integer> f : futures) {
                int st = f.get(15, TimeUnit.SECONDS);
                if (st == 201) {
                    created++;
                } else if (st == 409) {
                    conflicts++;
                } else {
                    fail("Unexpected status on concurrent registration race: " + st);
                }
            }
            assertEquals(1, created);
            assertEquals(threads - 1, conflicts);
            assertEquals(basePersons + 1, personRepository.count());
            assertEquals(baseTokens + 1, otpTokenRepository.count());
            assertEquals(baseUsers + 1, userRepository.count());
        } finally {
            pool.shutdownNow();
        }
    }

    // -------------------------------------------------------------------------
    // 6. ROLE_ADMIN authorization checks
    // -------------------------------------------------------------------------
    @Test
    void registrationEndpointsRequireAdminRole() throws Exception {
        OAuthClient client = createOAuthClient("reg-auth-oa", AuthMode.PASSWORD_ONLY);
        String payload = "{\"username\":\"unauth\",\"person\":{\"displayName\":\"No Auth\"}}";

        for (String endpoint : List.of("/v1/api/registration", "/v1/api/users/register")) {
            mockMvc.perform(post(endpoint).contentType(MediaType.APPLICATION_JSON).content(payload))
                    .andExpect(status().isUnauthorized());
            mockMvc.perform(post(endpoint).with(plainUser()).contentType(MediaType.APPLICATION_JSON).content(payload))
                    .andExpect(status().isForbidden());
            int bearerStatus = mockMvc.perform(post(endpoint).with(bearerFor(client))
                            .contentType(MediaType.APPLICATION_JSON).content(payload))
                    .andReturn().getResponse().getStatus();
            assertTrue(bearerStatus == 401 || bearerStatus == 403,
                    "OAuth bearer token must not access admin endpoint " + endpoint + ", got " + bearerStatus);
        }
    }

    private void assertCountsUnchanged(long persons, long tokens, long users) {
        assertEquals(persons, personRepository.count(), "No orphan Person rows allowed on rollback");
        assertEquals(tokens, otpTokenRepository.count(), "No orphan OtpToken rows allowed on rollback");
        assertEquals(users, userRepository.count(), "No orphan User rows allowed on rollback");
    }
}
