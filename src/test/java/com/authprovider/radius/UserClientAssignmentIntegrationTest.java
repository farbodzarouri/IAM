package com.authprovider.radius;

import com.authprovider.LdapAuthTest;
import com.authprovider.TestUsers;
import com.authprovider.entity.AuthMode;
import com.authprovider.entity.ClientScope;
import com.authprovider.entity.OAuthClient;
import com.authprovider.entity.RadiusClient;
import com.authprovider.entity.User;
import com.authprovider.entity.UserOAuthClient;
import com.authprovider.repository.OAuthClientRepository;
import com.authprovider.repository.PersonRepository;
import com.authprovider.repository.RadiusClientRepository;
import com.authprovider.repository.UserOAuthClientRepository;
import com.authprovider.repository.UserRadiusClientRepository;
import com.authprovider.repository.UserRepository;
import com.authprovider.service.SecretGenerator;
import com.authprovider.service.TotpService;
import com.authprovider.service.UserService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.binary.Base32;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.time.Clock;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static com.authprovider.OAuthTestSupport.bearerWithoutAssignments;
import static com.authprovider.radius.RadiusConstants.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Users must hold an enabled assignment to a RADIUS / OAuth 2.0 client to authenticate (or validate OTP / MFA)
 * through it; the assignment authMode overrides the client's.
 */
@SpringBootTest(properties = {
        "radius.port=0",
        "radius.bind-address=127.0.0.1",
        "iam.bootstrap.radius.shared-secret=assign-secret",
        "ldap.fallback-to-local=true"
})
@AutoConfigureMockMvc
class UserClientAssignmentIntegrationTest {

    private static final String PASSWORD = "Assign!Pass123";
    private static final String OTP_SECRET = "JBSWY3DPEHPK3PXP";
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final LdapAuthTest.MockLdapServer LDAP;

    static {
        try {
            LDAP = new LdapAuthTest.MockLdapServer();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @DynamicPropertySource
    static void ldap(DynamicPropertyRegistry registry) {
        registry.add("ldap.enabled", () -> "true");
        registry.add("ldap.url", () -> "ldap://localhost:" + LDAP.getPort());
        registry.add("ldap.base-dn", () -> "dc=example,dc=org");
        registry.add("ldap.user-search-filter", () -> "(&(objectClass=person)(|(uid={0})(sAMAccountName={0})))");
        registry.add("ldap.bind-dn", () -> "cn=admin,dc=example,dc=org");
        registry.add("ldap.bind-password", () -> "secret");
        registry.add("ldap.auto-provision", () -> "true");
    }

    @AfterAll
    static void stopLdap() {
        LDAP.close();
    }

    @Autowired private MockMvc mockMvc;
    @Autowired private RadiusServer radiusServer;
    @Autowired private UserService userService;
    @Autowired private UserRepository userRepository;
    @Autowired private RadiusClientRepository radiusClientRepository;
    @Autowired private OAuthClientRepository oauthClientRepository;
    @Autowired private PersonRepository personRepository;
    @Autowired private UserRadiusClientRepository radiusAssignmentRepository;
    @Autowired private UserOAuthClientRepository oauthAssignmentRepository;
    @Autowired private TotpService totpService;
    @Autowired private SecretGenerator secretGenerator;
    @Autowired private Clock clock;
    @Autowired private com.authprovider.service.AccountLockoutService lockoutService;
    @Autowired private com.authprovider.service.OtpUsageStore usageStore;

    private String suffix;

    @BeforeEach
    void setUp() {
        suffix = UUID.randomUUID().toString().substring(0, 8);
        usageStore.clear();
    }

    private static RequestPostProcessor admin() {
        return user("root").roles("ADMIN");
    }

    private RadiusClient defaultRadiusClient() {
        return radiusClientRepository.findAll().stream()
                .filter(c -> "assign-secret".equals(c.getSharedSecret()))
                .findFirst().orElseThrow();
    }

    private User createUser(String name) {
        User user = userService.saveUser(User.builder().username(name).password(PASSWORD)
                .otpToken(TestUsers.token(OTP_SECRET)).build());
        lockoutService.recordSuccess(user.getId());
        return user;
    }

    private OAuthClient oauthClient(String clientId, AuthMode mode) {
        return com.authprovider.OAuthTestSupport.ensureClient(context, clientId, mode,
                EnumSet.allOf(ClientScope.class));
    }

    @Autowired private org.springframework.context.ApplicationContext context;

    private RequestPostProcessor bearerOf(String clientId, AuthMode mode) {
        return bearerWithoutAssignments(clientId, mode, EnumSet.allOf(ClientScope.class));
    }

    private JsonNode login(String clientId, AuthMode clientMode, String username, String password, String otp)
            throws Exception {
        String body = "{\"username\":\"" + username + "\"" + (password == null ? "" : ",\"password\":\"" + password + "\"")
                + (otp == null ? "" : ",\"otp\":\"" + otp + "\"") + "}";
        String response = mockMvc.perform(post("/v1/api/auth/login").with(bearerOf(clientId, clientMode))
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andReturn().getResponse().getContentAsString();
        return JSON.readTree(response);
    }

    private int radius(String username, String password) throws Exception {
        try (RadiusTestClient client = new RadiusTestClient(radiusServer.getLocalPort(), "assign-secret")) {
            return client.sendExpectingResponse(client.accessRequest(username, password, null)).getCode();
        }
    }

    private void putAssignment(String type, Long userId, Long clientId, String body) throws Exception {
        mockMvc.perform(put("/v1/api/users/" + userId + "/" + type + "/" + clientId).with(admin())
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk());
    }

    // ---------------------------------------------------------------- client listing

    @Test
    void clientListingIsAdminOnlyTypedAndSecretFree() throws Exception {
        OAuthClient oauth = oauthClient("list-" + suffix, AuthMode.PASSWORD_ONLY);
        RadiusClient radiusClient = defaultRadiusClient();

        String all = mockMvc.perform(get("/v1/api/clients/all").with(admin()))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        JsonNode nodes = JSON.readTree(all);
        boolean foundOauth = false;
        boolean foundRadius = false;
        for (JsonNode n : nodes) {
            assertFalse(n.has("sharedSecret") || n.has("clientSecret") || n.has("clientSecretHash")
                    || n.has("secret") || n.has("tokenVersion"), "no secrets: " + n);
            if ("OAUTH2".equals(n.path("type").asText()) && n.path("id").asLong() == oauth.getId()) {
                foundOauth = true;
                assertEquals(oauth.getName(), n.path("name").asText());
                assertTrue(n.path("enabled").asBoolean());
                assertEquals("PASSWORD_ONLY", n.path("authMode").asText());
            }
            if ("RADIUS".equals(n.path("type").asText()) && n.path("id").asLong() == radiusClient.getId()) {
                foundRadius = true;
                assertEquals(radiusClient.getName(), n.path("name").asText());
            }
        }
        assertTrue(foundOauth && foundRadius, all);

        mockMvc.perform(get("/v1/api/clients/all").param("type", "RADIUS").with(admin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[*].type", org.hamcrest.Matchers.everyItem(org.hamcrest.Matchers.is("RADIUS"))));
        mockMvc.perform(get("/v1/api/clients/all").param("type", "OAUTH2").with(admin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[*].type", org.hamcrest.Matchers.everyItem(org.hamcrest.Matchers.is("OAUTH2"))));
        mockMvc.perform(get("/v1/api/clients/all").param("type", "LDAP").with(admin()))
                .andExpect(status().isBadRequest());
        mockMvc.perform(get("/v1/api/clients/all").with(user("operator").roles("USER")))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/v1/api/clients/all"))
                .andExpect(status().isUnauthorized());

        // OAuth client registry moved to /v1/api/oauth-clients
        mockMvc.perform(get("/v1/api/oauth-clients/all").with(admin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.id == " + oauth.getId() + ")].clientId").value(oauth.getClientId()));
        mockMvc.perform(get("/v1/api/oauth-clients/" + oauth.getId()).with(user("operator").roles("USER")))
                .andExpect(status().isForbidden());
    }

    // ---------------------------------------------------------------- assignment API

    @Test
    void assignmentEndpointsManageAssignmentsAndUserViewListsThem() throws Exception {
        User user = createUser("api-" + suffix);
        OAuthClient oauth = oauthClient("api-" + suffix, null);
        RadiusClient radiusClient = defaultRadiusClient();
        String base = "/v1/api/users/" + user.getId();

        mockMvc.perform(get(base + "/radius-clients").with(admin()))
                .andExpect(status().isOk()).andExpect(jsonPath("$.length()").value(0));
        mockMvc.perform(get(base + "/radius-clients/" + radiusClient.getId()).with(admin()))
                .andExpect(status().isNotFound());
        mockMvc.perform(put(base + "/radius-clients/" + radiusClient.getId()).with(user("op").roles("USER"))
                        .contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isForbidden());

        // PUT without body: enabled by default, no auth mode override
        mockMvc.perform(put(base + "/radius-clients/" + radiusClient.getId()).with(admin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.clientId").value(radiusClient.getId()))
                .andExpect(jsonPath("$.enabled").value(true))
                .andExpect(jsonPath("$.authMode").doesNotExist());
        putAssignment("oauth-clients", user.getId(), oauth.getId(), "{\"enabled\":false,\"authMode\":\"OTP_ONLY\"}");
        mockMvc.perform(get(base + "/oauth-clients/" + oauth.getId()).with(admin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.enabled").value(false))
                .andExpect(jsonPath("$.authMode").value("OTP_ONLY"));
        mockMvc.perform(put(base + "/oauth-clients/999999").with(admin())
                        .contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isNotFound());
        mockMvc.perform(put("/v1/api/users/999999/oauth-clients/" + oauth.getId()).with(admin())
                        .contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isNotFound());

        mockMvc.perform(get("/v1/api/users/" + user.getId()).with(admin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.authMode").doesNotExist())
                .andExpect(jsonPath("$.secret").doesNotExist())
                .andExpect(jsonPath("$.radiusClients[0].clientId").value(radiusClient.getId()))
                .andExpect(jsonPath("$.radiusClients[0].enabled").value(true))
                .andExpect(jsonPath("$.oauthClients[0].clientId").value(oauth.getId()))
                .andExpect(jsonPath("$.oauthClients[0].enabled").value(false))
                .andExpect(jsonPath("$.oauthClients[0].authMode").value("OTP_ONLY"));

        mockMvc.perform(delete(base + "/oauth-clients/" + oauth.getId()).with(admin()))
                .andExpect(status().isOk());
        mockMvc.perform(get(base + "/oauth-clients").with(admin()))
                .andExpect(status().isOk()).andExpect(jsonPath("$.length()").value(0));
        mockMvc.perform(delete(base + "/oauth-clients/" + oauth.getId()).with(admin()))
                .andExpect(status().isNotFound());

        // user payload lists replace the assignments
        mockMvc.perform(put("/v1/api/users/" + user.getId()).with(admin()).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"oauthClients\":[{\"clientId\":" + oauth.getId() + ",\"authMode\":\"PASSWORD_ONLY\"}],"
                                + "\"radiusClients\":[]}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.radiusClients.length()").value(0))
                .andExpect(jsonPath("$.oauthClients[0].enabled").value(true))
                .andExpect(jsonPath("$.oauthClients[0].authMode").value("PASSWORD_ONLY"));
        mockMvc.perform(put("/v1/api/users/" + user.getId()).with(admin()).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"oauthClients\":[{\"clientId\":424242}]}"))
                .andExpect(status().isBadRequest());
        String created = mockMvc.perform(post("/v1/api/users/create").with(admin()).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"created-" + suffix + "\",\"password\":\"" + PASSWORD + "\","
                                + "\"radiusClients\":[{\"clientId\":" + radiusClient.getId() + "}]}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.radiusClients[0].clientId").value(radiusClient.getId()))
                .andExpect(jsonPath("$.oauthClients.length()").value(0))
                .andReturn().getResponse().getContentAsString();
        long createdId = JSON.readTree(created).path("id").asLong();

        // deleting a client or user removes its assignments
        mockMvc.perform(delete("/v1/api/oauth-clients/" + oauth.getId()).with(admin())).andExpect(status().isOk());
        assertTrue(oauthAssignmentRepository.findByUserId(user.getId()).isEmpty());
        mockMvc.perform(delete("/v1/api/users/" + createdId).with(admin())).andExpect(status().isOk());
        assertTrue(radiusAssignmentRepository.findByUserId(createdId).isEmpty());
    }

    // ---------------------------------------------------------------- OAuth enforcement

    @Test
    void oauthLoginOtpAndMfaRequireEnabledAssignmentAndAssignmentAuthModeOverridesClient() throws Exception {
        String name = "rest-" + suffix;
        User user = createUser(name);
        String clientA = "rest-a-" + suffix;
        String clientB = "rest-b-" + suffix;
        OAuthClient a = oauthClient(clientA, AuthMode.PASSWORD_AND_OTP);
        oauthClient(clientB, AuthMode.PASSWORD_AND_OTP);

        // not assigned: refused everywhere (generic responses), before any credential is checked
        JsonNode refused = login(clientA, AuthMode.PASSWORD_AND_OTP, name, PASSWORD, null);
        assertEquals("INVALID_CREDENTIALS", refused.path("status").asText());
        String otp = String.format("%06d", totpService.generateOtp(OTP_SECRET));
        mockMvc.perform(post("/v1/api/otp/validate").with(bearerOf(clientA, AuthMode.PASSWORD_AND_OTP))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + name + "\",\"otp\":\"" + otp + "\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.valid").value(false));
        mockMvc.perform(post("/v1/api/mfa/preauth").with(bearerOf(clientA, AuthMode.PASSWORD_AND_OTP))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + name + "\",\"otp\":" + Integer.parseInt(otp) + "}"))
                .andExpect(status().isOk())
                .andExpect(content().string("false"));
        assertFalse(lockoutService.isLocked(user.getId()));

        // assignment authMode PASSWORD_ONLY overrides the client's PASSWORD_AND_OTP
        putAssignment("oauth-clients", user.getId(), a.getId(), "{\"authMode\":\"PASSWORD_ONLY\"}");
        JsonNode ok = login(clientA, AuthMode.PASSWORD_AND_OTP, name, PASSWORD, null);
        assertTrue(ok.path("authenticated").asBoolean(), ok.toString());
        // still not assigned to client B
        assertEquals("INVALID_CREDENTIALS",
                login(clientB, AuthMode.PASSWORD_AND_OTP, name, PASSWORD, null).path("status").asText());

        // inherit the client mode: OTP is required
        putAssignment("oauth-clients", user.getId(), a.getId(), "{}");
        assertEquals("OTP_REQUIRED", login(clientA, AuthMode.PASSWORD_AND_OTP, name, PASSWORD, null)
                .path("status").asText());
        mockMvc.perform(post("/v1/api/otp/validate").with(bearerOf(clientA, AuthMode.PASSWORD_AND_OTP))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + name + "\",\"otp\":\"" + otp + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true));

        // disabled assignment: refused again
        putAssignment("oauth-clients", user.getId(), a.getId(), "{\"enabled\":false,\"authMode\":\"PASSWORD_ONLY\"}");
        assertFalse(login(clientA, AuthMode.PASSWORD_AND_OTP, name, PASSWORD, null).path("authenticated").asBoolean());
    }

    // ---------------------------------------------------------------- RADIUS enforcement

    @Test
    void radiusRequiresEnabledAssignmentAndAssignmentAuthModeOverridesClient() throws Exception {
        String name = "nas-" + suffix;
        User user = createUser(name);
        RadiusClient client = defaultRadiusClient();

        assertEquals(ACCESS_REJECT, radius(name, PASSWORD));
        putAssignment("radius-clients", user.getId(), client.getId(), "{}");
        assertEquals(ACCESS_CHALLENGE, radius(name, PASSWORD));
        putAssignment("radius-clients", user.getId(), client.getId(), "{\"authMode\":\"PASSWORD_ONLY\"}");
        assertEquals(ACCESS_ACCEPT, radius(name, PASSWORD));
        putAssignment("radius-clients", user.getId(), client.getId(), "{\"enabled\":false,\"authMode\":\"PASSWORD_ONLY\"}");
        assertEquals(ACCESS_REJECT, radius(name, PASSWORD));
        assertFalse(lockoutService.isLocked(user.getId()));

        // an OAuth assignment does not grant RADIUS access
        OAuthClient oauth = oauthClient("nas-o-" + suffix, null);
        putAssignment("oauth-clients", user.getId(), oauth.getId(), "{\"authMode\":\"PASSWORD_ONLY\"}");
        mockMvc.perform(delete("/v1/api/users/" + user.getId() + "/radius-clients/" + client.getId()).with(admin()))
                .andExpect(status().isOk());
        assertEquals(ACCESS_REJECT, radius(name, PASSWORD));
    }

    // ---------------------------------------------------------------- LDAP auto-provisioning

    @Test
    void ldapAutoProvisionedUserIsAssignedOnlyToCallingOAuthClient() throws Exception {
        userRepository.findAllByUsernameIgnoreCase("bob").forEach(userRepository::delete);
        String caller = "ldap-caller-" + suffix;
        String other = "ldap-other-" + suffix;
        OAuthClient callerClient = oauthClient(caller, AuthMode.PASSWORD_ONLY);
        oauthClient(other, AuthMode.PASSWORD_ONLY);

        JsonNode first = login(caller, AuthMode.PASSWORD_ONLY, "bob", "BobLdapPass!", null);
        assertTrue(first.path("authenticated").asBoolean(), first.toString());
        User bob = userRepository.findAllByUsernameIgnoreCase("bob").get(0);
        List<UserOAuthClient> assignments = oauthAssignmentRepository.findByUserId(bob.getId());
        assertEquals(1, assignments.size());
        assertEquals(callerClient.getId(), assignments.get(0).getClientId());
        assertTrue(assignments.get(0).isEnabled());
        assertNull(assignments.get(0).getAuthMode());
        assertTrue(radiusAssignmentRepository.findByUserId(bob.getId()).isEmpty());

        assertTrue(login(caller, AuthMode.PASSWORD_ONLY, "bob", "BobLdapPass!", null).path("authenticated").asBoolean());
        assertFalse(login(other, AuthMode.PASSWORD_ONLY, "bob", "BobLdapPass!", null).path("authenticated").asBoolean());
        userRepository.delete(bob);
    }

    // ---------------------------------------------------------------- regression fixes

    @Test
    void crossClientChallengeAndMfaApprovalSurviveRevocationOfOtherClients() throws Exception {
        long step = stableCurrentStep();
        String secret = secretGenerator.generateSecret();
        User user = userService.saveUser(User.builder()
                .username("iso-chal-" + suffix)
                .password(PASSWORD)
                .otpToken(TestUsers.token(secret))
                .build());
        lockoutService.recordSuccess(user.getId());

        RadiusClient nasA = defaultRadiusClient();
        RadiusClient nasB = radiusClientRepository.saveAndFlush(RadiusClient.builder()
                .name("nas-b-" + suffix)
                .address("10.99.99.99/32")
                .sharedSecret("nas-b-secret-" + suffix)
                .active(true)
                .build());
        OAuthClient oaA = oauthClient("chal-oa-a-" + suffix, null);
        OAuthClient oaB = oauthClient("chal-oa-b-" + suffix, null);

        putAssignment("radius-clients", user.getId(), nasA.getId(), "{}");
        putAssignment("radius-clients", user.getId(), nasB.getId(), "{}");
        putAssignment("oauth-clients", user.getId(), oaA.getId(), "{}");
        putAssignment("oauth-clients", user.getId(), oaB.getId(), "{}");

        // Issue Turn-1 Challenge AND OOB MFA approval BEFORE revoking nasB / oaB
        byte[] state;
        try (RadiusTestClient client = new RadiusTestClient(radiusServer.getLocalPort(), "assign-secret")) {
            RadiusPacket ch = client.sendExpectingResponse(client.accessRequest(user.getUsername(), PASSWORD, null));
            assertEquals(ACCESS_CHALLENGE, ch.getCode());
            state = ch.getAttribute(ATTR_STATE).orElseThrow().getValue();
        }
        String oobOtp = otpForStep(secret, step - 1);
        mockMvc.perform(post("/v1/api/mfa/preauth").with(bearerOf(oaA.getClientId(), null))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + user.getUsername() + "\",\"otp\":" + Integer.parseInt(oobOtp) + "}"))
                .andExpect(status().isOk())
                .andExpect(content().string("true"));

        // Revoke nasB and oaB -> must NOT break nasA in-flight challenge or OOB approval!
        putAssignment("radius-clients", user.getId(), nasB.getId(), "{\"enabled\":false}");
        mockMvc.perform(delete("/v1/api/users/" + user.getId() + "/oauth-clients/" + oaB.getId()).with(admin()))
                .andExpect(status().isOk());

        try (RadiusTestClient client = new RadiusTestClient(radiusServer.getLocalPort(), "assign-secret")) {
            // In-flight challenge completes with Access-Accept
            assertEquals(ACCESS_ACCEPT,
                    client.sendExpectingResponse(client.accessRequest(user.getUsername(), otpForStep(secret, step), state)).getCode());
            // OOB approval still succeeds on nasA
            assertEquals(ACCESS_ACCEPT,
                    client.sendExpectingResponse(client.accessRequest(user.getUsername(), null, null)).getCode());

            // Now issue a fresh challenge on nasA, then disable nasA itself -> Turn-2 must return Access-Reject
            RadiusPacket ch2 = client.sendExpectingResponse(client.accessRequest(user.getUsername(), PASSWORD, null));
            assertEquals(ACCESS_CHALLENGE, ch2.getCode());
            byte[] state2 = ch2.getAttribute(ATTR_STATE).orElseThrow().getValue();
            putAssignment("radius-clients", user.getId(), nasA.getId(), "{\"enabled\":false}");
            assertEquals(ACCESS_REJECT,
                    client.sendExpectingResponse(client.accessRequest(user.getUsername(), otpForStep(secret, step + 1), state2)).getCode());
        } finally {
            radiusAssignmentRepository.deleteByClientId(nasB.getId());
            radiusClientRepository.delete(nasB);
        }
    }

    @Test
    void radiusPasswordOnlyLdapRejectDoesNotCreateGhostUserAndAllowsSubsequentOAuthJit() throws Exception {
        userRepository.findAllByUsernameIgnoreCase("bob").forEach(u -> userService.deleteUser(u.getId()));
        RadiusClient radiusClient = defaultRadiusClient();
        AuthMode previousMode = radiusClient.getAuthMode();
        radiusClient.setAuthMode(AuthMode.PASSWORD_ONLY);
        radiusClientRepository.saveAndFlush(radiusClient);
        try {
            // Valid LDAP user "bob" with PASSWORD_ONLY NAS must reject AND create zero local User rows
            assertEquals(ACCESS_REJECT, radius("bob", "BobLdapPass!"));
            assertTrue(userRepository.findAllByUsernameIgnoreCase("bob").isEmpty(),
                    "RADIUS must never auto-provision a local User on rejected LDAP request");

            // Subsequent OAuth PASSWORD_ONLY login with autoProvision=true provisions bob & assigns calling client only
            String caller = "jit-after-rad-" + suffix;
            OAuthClient callerClient = oauthClient(caller, AuthMode.PASSWORD_ONLY);
            JsonNode resp = login(caller, AuthMode.PASSWORD_ONLY, "bob", "BobLdapPass!", null);
            assertTrue(resp.path("authenticated").asBoolean(), resp.toString());

            User bob = userRepository.findAllByUsernameIgnoreCase("bob").stream().findFirst().orElseThrow();
            List<UserOAuthClient> oaBindings = oauthAssignmentRepository.findByUserId(bob.getId());
            assertEquals(1, oaBindings.size());
            assertEquals(callerClient.getId(), oaBindings.get(0).getClientId());
            userService.deleteUser(bob.getId());
        } finally {
            radiusClient.setAuthMode(previousMode);
            radiusClientRepository.saveAndFlush(radiusClient);
        }
    }

    @Test
    void concurrentAssignmentPutUpsertsReturnOkWithoutDuplicatesOrServerErrors() throws Exception {
        User user = createUser("conc-put-" + suffix);
        OAuthClient oauth = oauthClient("conc-oa-" + suffix, null);
        RadiusClient radiusClient = defaultRadiusClient();

        int threads = 8;
        CountDownLatch startGate = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(threads * 2);
        List<Future<Integer>> futures = new ArrayList<>();
        try {
            for (int i = 0; i < threads; i++) {
                futures.add(pool.submit(() -> {
                    startGate.await(5, TimeUnit.SECONDS);
                    return mockMvc.perform(put("/v1/api/users/" + user.getId() + "/oauth-clients/" + oauth.getId())
                                    .with(admin())
                                    .contentType(MediaType.APPLICATION_JSON)
                                    .content("{\"enabled\":true}"))
                            .andReturn().getResponse().getStatus();
                }));
                futures.add(pool.submit(() -> {
                    startGate.await(5, TimeUnit.SECONDS);
                    return mockMvc.perform(put("/v1/api/users/" + user.getId() + "/radius-clients/" + radiusClient.getId())
                                    .with(admin())
                                    .contentType(MediaType.APPLICATION_JSON)
                                    .content("{\"enabled\":true}"))
                            .andReturn().getResponse().getStatus();
                }));
            }
            startGate.countDown();
            for (Future<Integer> future : futures) {
                int status = future.get(15, TimeUnit.SECONDS);
                assertTrue(status == 200 || status == 201 || status == 409,
                        "Concurrent assignment PUT must return 2xx or 409, never 500, got " + status);
            }
        } finally {
            pool.shutdownNow();
        }
        assertEquals(1, oauthAssignmentRepository.findByUserId(user.getId()).size());
        assertEquals(1, radiusAssignmentRepository.findByUserId(user.getId()).size());
    }

    @Test
    void invalidUserPayloadAssignmentsRollBackEntireCreateAndUpdateTransactions() throws Exception {
        long baselineUsers = userRepository.count();
        long baselinePersons = personRepository.count();

        // Failing POST /v1/api/users/create with unknown radius client must leave 0 new User or Person rows
        mockMvc.perform(post("/v1/api/users/create").with(admin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"rollback-" + suffix + "\",\"password\":\"" + PASSWORD
                                + "\",\"radiusClients\":[{\"clientId\":999999}]}"))
                .andExpect(status().isBadRequest());
        assertEquals(baselineUsers, userRepository.count());
        assertEquals(baselinePersons, personRepository.count());

        // Failing PUT /v1/api/users/{id} with unknown oauth client must roll back username/enabled changes too
        User existing = createUser("rollback-upd-" + suffix);
        String originalUsername = existing.getUsername();
        mockMvc.perform(put("/v1/api/users/" + existing.getId()).with(admin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"renamed-should-rollback-" + suffix
                                + "\",\"enabled\":false,\"oauthClients\":[{\"clientId\":999999}]}"))
                .andExpect(status().isBadRequest());
        User reloaded = userRepository.findById(existing.getId()).orElseThrow();
        assertEquals(originalUsername, reloaded.getUsername());
        assertTrue(reloaded.isEnabled());
    }

    private long stableCurrentStep() throws InterruptedException {
        while (clock.millis() % 30_000L > 22_000L) {
            Thread.sleep(200);
        }
        return clock.millis() / 30_000L;
    }

    private static String otpForStep(String secret, long step) {
        try {
            byte[] key = new Base32().decode(secret);
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
            throw new IllegalStateException(e);
        }
    }
}
