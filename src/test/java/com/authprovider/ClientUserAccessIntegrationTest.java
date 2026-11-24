package com.authprovider;

import com.authprovider.config.DatabaseConfigurationBootstrap;
import com.authprovider.entity.AuthMode;
import com.authprovider.entity.LdapDirectory;
import com.authprovider.entity.SecurityPolicy;
import com.authprovider.entity.User;
import com.authprovider.radius.RadiusServer;
import com.authprovider.repository.AuthFailureRecordRepository;
import com.authprovider.repository.LdapDirectoryRepository;
import com.authprovider.repository.MfaApprovalRepository;
import com.authprovider.repository.OcraChallengeUseRepository;
import com.authprovider.repository.OtpReplayStateRepository;
import com.authprovider.repository.RadiusChallengeSessionRepository;
import com.authprovider.repository.SecurityPolicyRepository;
import com.authprovider.repository.UserRepository;
import com.authprovider.service.OcraService;
import com.authprovider.service.SecretGenerator;
import com.authprovider.service.TotpService;
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
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;

@SpringBootTest(properties = {
        "radius.port=0",
        "radius.bind-address=0.0.0.0",
        "iam.bootstrap.radius.shared-secret=BootRadSec_9876543210_ZxQvBnM9_Aa7Kp2Lm4Q",
        "iam.bootstrap.admin.username=grader-boot-admin",
        "iam.bootstrap.admin.password=GraderBootAdm!123_Aa7Kp2Lm4Qx8Tz1B",
        "iam.bootstrap.policy.max-failures=5",
        "iam.bootstrap.policy.lockout-seconds=120",
        "iam.bootstrap.policy.mfa-approval-ttl-seconds=60",
        "iam.bootstrap.policy.challenge-ttl-seconds=60"
})
@AutoConfigureMockMvc
class ClientUserAccessIntegrationTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Base32 BASE32 = new Base32();
    private static final String USER_PASS = "Str0ng!UserPass9_Aa7Kp2Lm4Qx8Tz1B";
    private static final String LDAP_BIND_PASSWORD = "LdapBindSec_9876543210_ZxQvBnM9_Aa7Kp2Lm";
    private static final List<String> ALL_SCOPES = List.of("auth:login", "otp:validate", "mfa:preauth");

    @Autowired private MockMvc mockMvc;
    @Autowired private RadiusServer radiusServer;
    @Autowired private DatabaseConfigurationBootstrap bootstrap;
    @Autowired private UserService userService;
    @Autowired private UserRepository userRepository;
    @Autowired private SecurityPolicyRepository policyRepository;
    @Autowired private LdapDirectoryRepository ldapDirectoryRepository;
    @Autowired private AuthFailureRecordRepository failureRepository;
    @Autowired private MfaApprovalRepository approvalRepository;
    @Autowired private RadiusChallengeSessionRepository challengeRepository;
    @Autowired private OtpReplayStateRepository replayRepository;
    @Autowired private OcraChallengeUseRepository ocraRepository;
    @Autowired private TotpService totpService;
    @Autowired private OcraService ocraService;
    @Autowired private SecretGenerator secretGenerator;
    @Autowired private Clock clock;

    private final SecureRandom secureRandom = new SecureRandom();

    private record CreatedOAuthClient(long id, String clientId, String clientSecret) {
    }

    private record CreatedUser(long id, String username, long personId, Long otpTokenId, String secret) {
    }

    private record AssignmentSpec(long clientId, Boolean enabled, AuthMode authMode) {
    }

    @BeforeEach
    void setUp() throws Exception {
        cleanState();
        if (policyRepository.count() == 0) {
            bootstrap.seed();
        }
        configurePolicy(AuthMode.PASSWORD_AND_OTP, 5);
    }

    @AfterEach
    void tearDown() throws Exception {
        cleanState();
        configurePolicy(AuthMode.PASSWORD_AND_OTP, 5);
    }

    private void cleanState() throws Exception {
        for (User existing : userRepository.findAll()) {
            try {
                if (existing.getId() != null) {
                    userService.deleteUser(existing.getId());
                }
            } catch (Exception ignored) {
            }
        }
        deleteAllOAuthClients();
        deleteAllRadiusClients();
        challengeRepository.deleteAll();
        approvalRepository.deleteAll();
        failureRepository.deleteAll();
        replayRepository.deleteAll();
        ocraRepository.deleteAll();
        resetDirectories();
    }

    private void deleteAllOAuthClients() throws Exception {
        MvcResult list = mockMvc.perform(get("/v1/api/oauth-clients/all").with(adminUser())).andReturn();
        int status = list.getResponse().getStatus();
        if (status == 404 || status == 405) {
            list = mockMvc.perform(get("/v1/api/oauth-clients").with(adminUser())).andReturn();
            status = list.getResponse().getStatus();
        }
        if (status == 200) {
            JsonNode arr = JSON.readTree(list.getResponse().getContentAsString());
            if (arr != null && arr.isArray()) {
                for (JsonNode c : arr) {
                    if (c.hasNonNull("id")) {
                        mockMvc.perform(delete("/v1/api/oauth-clients/" + c.get("id").asLong()).with(adminUser()));
                    }
                }
            }
        }
    }

    private void deleteAllRadiusClients() throws Exception {
        MvcResult list = mockMvc.perform(get("/v1/api/radius-clients/all").with(adminUser())).andReturn();
        if (list.getResponse().getStatus() == 200) {
            JsonNode arr = JSON.readTree(list.getResponse().getContentAsString());
            if (arr != null && arr.isArray()) {
                for (JsonNode c : arr) {
                    if (c.hasNonNull("id")) {
                        mockMvc.perform(delete("/v1/api/radius-clients/" + c.get("id").asLong()).with(adminUser()));
                    }
                }
            }
        }
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

    private void configurePolicy(AuthMode defaultAuthMode, int maxFailures) {
        SecurityPolicy policy = policyRepository.findByName(SecurityPolicy.DEFAULT_NAME).orElseThrow();
        policy.setDefaultAuthMode(defaultAuthMode);
        policy.setMaxFailures(maxFailures);
        policy.setMfaMaxFailedAttempts(maxFailures);
        policy.setLockoutSeconds(120);
        policy.setFailureWindowSeconds(120);
        policy.setMfaLockoutWindowSeconds(120);
        policy.setMfaOutOfBandEnabled(true);
        policy.setRequireMessageAuthenticator(false);
        policy.setStripRealm(true);
        policyRepository.saveAndFlush(policy);
    }

    private static RequestPostProcessor adminUser() {
        return SecurityMockMvcRequestPostProcessors.user("grader-boot-admin").roles("ADMIN");
    }

    private static RequestPostProcessor plainUser() {
        return SecurityMockMvcRequestPostProcessors.user("plain-end-user").roles("USER");
    }

    private static RequestPostProcessor bearerHeader(String accessToken) {
        return request -> {
            request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);
            return request;
        };
    }

    private static String uniqueSuffix() {
        return UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    }

    private static String oauthSecret(String tag) {
        String clean = tag.replaceAll("[^A-Za-z0-9_-]", "_");
        String base = "M2mClientSec_" + clean + "_9876543210_ZxQvBnM9-Aa.7";
        return base.length() <= 60 ? base : base.substring(0, 60);
    }

    private static String radiusSecret(String tag) {
        String clean = tag.replaceAll("[^A-Za-z0-9_-]", "_");
        String base = "RadSharedSec_" + clean + "_9876543210_ZxQvBnM9_Aa7K";
        return base.length() <= 56 ? base : base.substring(0, 56);
    }

    private static void assertSuccess2xx(int status, String context) {
        assertTrue(status >= 200 && status < 300,
                context + " expected HTTP 2xx but got " + status);
    }

    private static void assertDeleteOk(int status, String context) {
        assertTrue(status == 200 || status == 204,
                context + " expected HTTP 200 or 204 but got " + status);
    }

    private static void assertRejected4xx(int status, String context) {
        assertTrue(status >= 400 && status < 500 && status != 404 && status != 405,
                context + " expected 4xx (not 404/405) but got " + status);
    }

    private static void assertJsonFieldNotTrue(MvcResult res, String field) throws Exception {
        String raw = res.getResponse().getContentAsString();
        if (raw == null || raw.isBlank()) {
            return;
        }
        String trimmed = raw.trim();
        if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) {
            return;
        }
        JsonNode json = JSON.readTree(trimmed);
        assertFalse(json.path(field).asBoolean(false),
                "Denied response must not return " + field + "=true: " + raw);
    }

    private long createPerson(String displayName) throws Exception {
        MvcResult res = mockMvc.perform(post("/v1/api/persons/create").with(adminUser())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of("displayName", displayName, "enabled", true))))
                .andReturn();
        assertSuccess2xx(res.getResponse().getStatus(), "createPerson");
        return JSON.readTree(res.getResponse().getContentAsString()).get("id").asLong();
    }

    private long createToken(long personId, String label, String secret) throws Exception {
        MvcResult res = mockMvc.perform(post("/v1/api/persons/" + personId + "/tokens").with(adminUser())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of("label", label, "secret", secret))))
                .andReturn();
        assertSuccess2xx(res.getResponse().getStatus(), "createToken");
        return JSON.readTree(res.getResponse().getContentAsString()).get("id").asLong();
    }

    private JsonNode createUserViaApi(String username, String password, Long personId, Long otpTokenId) throws Exception {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("username", username);
        if (password != null) {
            body.put("password", password);
        }
        if (personId != null) {
            body.put("personId", personId);
        }
        if (otpTokenId != null) {
            body.put("otpTokenId", otpTokenId);
        }
        body.put("enabled", true);
        MvcResult res = mockMvc.perform(post("/v1/api/users/create").with(adminUser())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(body)))
                .andReturn();
        assertSuccess2xx(res.getResponse().getStatus(), "createUser");
        return JSON.readTree(res.getResponse().getContentAsString());
    }

    private CreatedUser createUserWithToken(String prefix, String secret,
                                            List<AssignmentSpec> oauthAssignments,
                                            List<AssignmentSpec> radiusAssignments) throws Exception {
        String username = prefix + "-" + uniqueSuffix();
        long personId = createPerson("Person " + username);
        Long tokenId = secret == null ? null : createToken(personId, "totp-" + username, secret);
        JsonNode json = createUserViaApi(username, USER_PASS, personId, tokenId);
        long userId = json.get("id").asLong();
        if (oauthAssignments != null) {
            for (AssignmentSpec spec : oauthAssignments) {
                putOAuthAssignment(userId, spec.clientId(), spec.enabled(), spec.authMode(), false);
            }
        }
        if (radiusAssignments != null) {
            for (AssignmentSpec spec : radiusAssignments) {
                putRadiusAssignment(userId, spec.clientId(), spec.enabled(), spec.authMode(), false);
            }
        }
        return new CreatedUser(userId, username, personId, tokenId, secret);
    }

    private CreatedOAuthClient createOAuthClient(String name, AuthMode authMode, boolean enabled, List<String> scopes)
            throws Exception {
        String clientId = name + "-" + uniqueSuffix();
        String clientSecret = oauthSecret(clientId);
        Map<String, Object> req = new LinkedHashMap<>();
        req.put("clientId", clientId);
        req.put("clientSecret", clientSecret);
        req.put("name", name);
        req.put("enabled", enabled);
        req.put("blocked", false);
        req.put("scopes", scopes);
        if (authMode != null) {
            req.put("authMode", authMode.name());
        }
        String payload = JSON.writeValueAsString(req);
        MvcResult res = mockMvc.perform(post("/v1/api/oauth-clients/create").with(adminUser())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andReturn();
        int status = res.getResponse().getStatus();
        if (status == 404 || status == 405) {
            res = mockMvc.perform(post("/v1/api/oauth-clients").with(adminUser())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(payload))
                    .andReturn();
            status = res.getResponse().getStatus();
        }
        assertSuccess2xx(status, "createOAuthClient(" + name + ")");
        JsonNode json = JSON.readTree(res.getResponse().getContentAsString());
        return new CreatedOAuthClient(json.get("id").asLong(), json.get("clientId").asText(), clientSecret);
    }

    private String fetchBearerToken(CreatedOAuthClient client) throws Exception {
        String basic = Base64.getEncoder().encodeToString(
                (client.clientId() + ":" + client.clientSecret()).getBytes(StandardCharsets.UTF_8));
        MvcResult res = mockMvc.perform(post("/oauth2/token")
                        .header(HttpHeaders.AUTHORIZATION, "Basic " + basic)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "client_credentials"))
                .andReturn();
        assertEquals(200, res.getResponse().getStatus(),
                "Expected /oauth2/token 200 for " + client.clientId() + " but got " + res.getResponse().getStatus());
        return JSON.readTree(res.getResponse().getContentAsString()).get("access_token").asText();
    }

    private long createRadiusClient(String name, String address, String sharedSecret, boolean active, AuthMode authMode)
            throws Exception {
        Map<String, Object> req = new LinkedHashMap<>();
        req.put("name", name + "-" + uniqueSuffix());
        req.put("address", address);
        req.put("sharedSecret", sharedSecret);
        req.put("active", active);
        if (authMode != null) {
            req.put("authMode", authMode.name());
        }
        MvcResult res = mockMvc.perform(post("/v1/api/radius-clients/create").with(adminUser())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(req)))
                .andReturn();
        assertSuccess2xx(res.getResponse().getStatus(), "createRadiusClient(" + name + ")");
        return JSON.readTree(res.getResponse().getContentAsString()).get("id").asLong();
    }

    private static AssignmentSpec binding(long clientId, Boolean enabled, AuthMode authMode) {
        return new AssignmentSpec(clientId, enabled, authMode);
    }

    private MvcResult putOAuthAssignment(long userId, long clientId, Boolean enabled, AuthMode authMode,
                                         boolean explicitNullAuthMode) throws Exception {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("clientId", clientId);
        if (enabled != null) {
            body.put("enabled", enabled);
        }
        if (authMode != null) {
            body.put("authMode", authMode.name());
        } else if (explicitNullAuthMode) {
            body.put("authMode", null);
        }
        MvcResult res = mockMvc.perform(put("/v1/api/users/" + userId + "/oauth-clients/" + clientId)
                        .with(adminUser())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(body)))
                .andReturn();
        assertSuccess2xx(res.getResponse().getStatus(), "putOAuthAssignment");
        return res;
    }

    private MvcResult putRadiusAssignment(long userId, long clientId, Boolean enabled, AuthMode authMode,
                                          boolean explicitNullAuthMode) throws Exception {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("clientId", clientId);
        if (enabled != null) {
            body.put("enabled", enabled);
        }
        if (authMode != null) {
            body.put("authMode", authMode.name());
        } else if (explicitNullAuthMode) {
            body.put("authMode", null);
        }
        MvcResult res = mockMvc.perform(put("/v1/api/users/" + userId + "/radius-clients/" + clientId)
                        .with(adminUser())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(body)))
                .andReturn();
        assertSuccess2xx(res.getResponse().getStatus(), "putRadiusAssignment");
        return res;
    }

    // -------------------------------------------------------------------------
    // 1. User entity cleanup: authMode and legacy secret removed
    // -------------------------------------------------------------------------
    @Test
    void userEntityRemovesAuthModeAndLegacySecretFields() throws Exception {
        Set<String> declaredFields = Arrays.stream(User.class.getDeclaredFields())
                .map(Field::getName)
                .collect(Collectors.toSet());
        assertFalse(declaredFields.contains("authMode"),
                "User entity must no longer declare authMode");
        assertFalse(declaredFields.contains("secret"),
                "User entity must no longer declare legacy secret column");

        deleteAllRadiusClients();
        CreatedOAuthClient oauthA = createOAuthClient("otp-check", null, true, ALL_SCOPES);
        long rcA = createRadiusClient("user-check-rc", "127.0.0.1", radiusSecret("user-check-rc"), true, null);
        long step = stableCurrentStep();
        String secret = distinctSecret(step);
        CreatedUser u = createUserWithToken("clean-user", secret,
                List.of(binding(oauthA.id(), true, AuthMode.OTP_ONLY)),
                List.of(binding(rcA, true, null)));

        MvcResult getRes = mockMvc.perform(get("/v1/api/users/" + u.id()).with(adminUser())).andReturn();
        assertEquals(200, getRes.getResponse().getStatus());
        JsonNode userJson = JSON.readTree(getRes.getResponse().getContentAsString());
        assertTrue(userJson.path("authMode").isMissingNode() || userJson.path("authMode").isNull(),
                "User JSON response must not expose authMode");
        assertTrue(userJson.path("secret").isMissingNode() || userJson.path("secret").isNull(),
                "User JSON response must not expose secret");
        assertTrue(userJson.has("oauthClients") && userJson.get("oauthClients").isArray());
        assertTrue(userJson.has("radiusClients") && userJson.get("radiusClients").isArray());

        String bearerA = fetchBearerToken(oauthA);
        String otp = otpForStep(secret, step);
        MvcResult loginRes = mockMvc.perform(post("/v1/api/auth/login").with(bearerHeader(bearerA))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of("username", u.username(), "otp", otp))))
                .andReturn();
        assertEquals(200, loginRes.getResponse().getStatus());
        JsonNode loginJson = JSON.readTree(loginRes.getResponse().getContentAsString());
        assertEquals("AUTHENTICATED", loginJson.get("status").asText());
        assertTrue(loginJson.get("authenticated").asBoolean());
    }

    // -------------------------------------------------------------------------
    // 2. OAuthClientController rename & unified admin /v1/api/clients/all
    // -------------------------------------------------------------------------
    @Test
    void oauthClientControllerRenamedAndUnifiedClientListingWorksByType() throws Exception {
        assertDoesNotThrow(() -> Class.forName("com.authprovider.controller.OAuthClientController"),
                "OAuthClientController class must exist");
        assertDoesNotThrow(() -> Class.forName("com.authprovider.controller.ClientController"),
                "ClientController class must exist for unified listing");

        // Full /v1/api/oauth-clients CRUD
        CreatedOAuthClient cActive = createOAuthClient("portal-main", AuthMode.OTP_ONLY, true, ALL_SCOPES);
        CreatedOAuthClient cDisabled = createOAuthClient("portal-disabled", null, false, List.of("auth:login"));

        MvcResult listOAuth = mockMvc.perform(get("/v1/api/oauth-clients/all").with(adminUser())).andReturn();
        if (listOAuth.getResponse().getStatus() == 404 || listOAuth.getResponse().getStatus() == 405) {
            listOAuth = mockMvc.perform(get("/v1/api/oauth-clients").with(adminUser())).andReturn();
        }
        assertEquals(200, listOAuth.getResponse().getStatus());
        JsonNode oauthArr = JSON.readTree(listOAuth.getResponse().getContentAsString());
        assertTrue(oauthArr.isArray() && oauthArr.size() >= 2);

        MvcResult getSingle = mockMvc.perform(get("/v1/api/oauth-clients/" + cActive.id()).with(adminUser())).andReturn();
        assertEquals(200, getSingle.getResponse().getStatus());
        String singleBody = getSingle.getResponse().getContentAsString();
        JsonNode singleJson = JSON.readTree(singleBody);
        assertTrue(singleJson.path("clientSecret").isMissingNode() || singleJson.path("clientSecret").isNull());
        assertNoSecretMaterialInBody(singleBody, cActive.clientSecret(), cDisabled.clientSecret());

        MvcResult updateRes = mockMvc.perform(put("/v1/api/oauth-clients/" + cActive.id()).with(adminUser())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of("name", "portal-main-updated"))))
                .andReturn();
        assertEquals(200, updateRes.getResponse().getStatus());
        assertEquals("portal-main-updated", JSON.readTree(updateRes.getResponse().getContentAsString()).get("name").asText());

        MvcResult rotateRes = mockMvc.perform(post("/v1/api/oauth-clients/" + cActive.id() + "/rotate-secret")
                        .with(adminUser()))
                .andReturn();
        assertEquals(200, rotateRes.getResponse().getStatus());
        String newSecret = JSON.readTree(rotateRes.getResponse().getContentAsString()).get("clientSecret").asText();
        assertNotEquals(cActive.clientSecret(), newSecret);
        // Verify rotated secret mints a token while old secret fails with 4xx
        fetchBearerToken(new CreatedOAuthClient(cActive.id(), cActive.clientId(), newSecret));
        String oldBasic = Base64.getEncoder().encodeToString(
                (cActive.clientId() + ":" + cActive.clientSecret()).getBytes(StandardCharsets.UTF_8));
        MvcResult oldTok = mockMvc.perform(post("/oauth2/token")
                        .header(HttpHeaders.AUTHORIZATION, "Basic " + oldBasic)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "client_credentials"))
                .andReturn();
        assertRejected4xx(oldTok.getResponse().getStatus(), "Old rotated OAuth client secret on /oauth2/token");

        // Create RADIUS clients to appear alongside OAuth clients in unified /v1/api/clients/all
        deleteAllRadiusClients();
        String radSec1 = radiusSecret("cat-1");
        String radSec2 = radiusSecret("cat-2");
        long radId = createRadiusClient("vpn-edge", "127.0.0.1", radSec1, true, AuthMode.PASSWORD_ONLY);
        long radDisabledId = createRadiusClient("vpn-inactive", "127.0.0.2", radSec2, false, null);

        // Unified GET /v1/api/clients/all (unfiltered)
        MvcResult unifiedAll = mockMvc.perform(get("/v1/api/clients/all").with(adminUser())).andReturn();
        assertEquals(200, unifiedAll.getResponse().getStatus());
        String unifiedAllBody = unifiedAll.getResponse().getContentAsString();
        assertNoSecretMaterialInBody(unifiedAllBody, cActive.clientSecret(), newSecret, cDisabled.clientSecret(), radSec1, radSec2);
        JsonNode allArr = JSON.readTree(unifiedAllBody);
        assertTrue(allArr.isArray() && allArr.size() >= 4);

        JsonNode foundOAuth = findCatalogEntry(allArr, "OAUTH2", cActive.id());
        assertNotNull(foundOAuth, "Unified listing must include active OAUTH2 client");
        assertEquals("portal-main-updated", foundOAuth.get("name").asText());
        assertTrue(foundOAuth.get("enabled").asBoolean());
        assertEquals("OTP_ONLY", foundOAuth.get("authMode").asText());

        JsonNode foundOAuthDisabled = findCatalogEntry(allArr, "OAUTH2", cDisabled.id());
        assertNotNull(foundOAuthDisabled, "Unified listing must include disabled OAUTH2 client");
        assertFalse(foundOAuthDisabled.get("enabled").asBoolean());

        JsonNode foundRadius = findCatalogEntry(allArr, "RADIUS", radId);
        assertNotNull(foundRadius, "Unified listing must include active RADIUS client");
        assertTrue(foundRadius.get("enabled").asBoolean());
        assertEquals("PASSWORD_ONLY", foundRadius.get("authMode").asText());

        JsonNode foundRadiusDisabled = findCatalogEntry(allArr, "RADIUS", radDisabledId);
        assertNotNull(foundRadiusDisabled, "Unified listing must include inactive RADIUS client with enabled=false");
        assertFalse(foundRadiusDisabled.get("enabled").asBoolean());

        for (JsonNode entry : allArr) {
            assertTrue(entry.hasNonNull("id"));
            assertTrue(entry.hasNonNull("type"));
            assertTrue(entry.hasNonNull("name"));
            assertTrue(entry.hasNonNull("enabled"));
            assertNoClientSecretsExposed(entry);
        }

        // Filter ?type=RADIUS
        MvcResult onlyRadius = mockMvc.perform(get("/v1/api/clients/all").param("type", "RADIUS").with(adminUser()))
                .andReturn();
        assertEquals(200, onlyRadius.getResponse().getStatus());
        String onlyRadiusBody = onlyRadius.getResponse().getContentAsString();
        assertNoSecretMaterialInBody(onlyRadiusBody, cActive.clientSecret(), newSecret, cDisabled.clientSecret(), radSec1, radSec2);
        JsonNode radOnlyArr = JSON.readTree(onlyRadiusBody);
        assertTrue(radOnlyArr.isArray() && radOnlyArr.size() >= 2);
        for (JsonNode entry : radOnlyArr) {
            assertEquals("RADIUS", entry.get("type").asText());
            assertNoClientSecretsExposed(entry);
        }
        assertNotNull(findCatalogEntry(radOnlyArr, "RADIUS", radId));

        // Filter ?type=OAUTH2
        MvcResult onlyOAuth = mockMvc.perform(get("/v1/api/clients/all").param("type", "OAUTH2").with(adminUser()))
                .andReturn();
        assertEquals(200, onlyOAuth.getResponse().getStatus());
        String onlyOAuthBody = onlyOAuth.getResponse().getContentAsString();
        assertNoSecretMaterialInBody(onlyOAuthBody, cActive.clientSecret(), newSecret, cDisabled.clientSecret(), radSec1, radSec2);
        JsonNode oauthOnlyArr = JSON.readTree(onlyOAuthBody);
        assertTrue(oauthOnlyArr.isArray() && oauthOnlyArr.size() >= 2);
        for (JsonNode entry : oauthOnlyArr) {
            assertEquals("OAUTH2", entry.get("type").asText());
            assertNoClientSecretsExposed(entry);
        }
        assertNotNull(findCatalogEntry(oauthOnlyArr, "OAUTH2", cActive.id()));

        // Invalid type -> 4xx
        MvcResult invalidType = mockMvc.perform(get("/v1/api/clients/all").param("type", "INVALID").with(adminUser()))
                .andReturn();
        assertRejected4xx(invalidType.getResponse().getStatus(), "Invalid ?type=INVALID on /v1/api/clients/all");

        // Admin-only enforcement on /v1/api/clients/all (no OAuth Bearer access)
        CreatedOAuthClient rotatedClient = new CreatedOAuthClient(cActive.id(), cActive.clientId(), newSecret);
        String bearer = fetchBearerToken(rotatedClient);
        assertRejected4xx(mockMvc.perform(get("/v1/api/clients/all")).andReturn().getResponse().getStatus(),
                "Anonymous on /v1/api/clients/all");
        assertRejected4xx(mockMvc.perform(get("/v1/api/clients/all").with(plainUser())).andReturn().getResponse().getStatus(),
                "ROLE_USER on /v1/api/clients/all");
        assertRejected4xx(mockMvc.perform(get("/v1/api/clients/all").with(bearerHeader(bearer)))
                .andReturn().getResponse().getStatus(), "Bearer on /v1/api/clients/all");

        // Delete OAuth client
        MvcResult delOAuth = mockMvc.perform(delete("/v1/api/oauth-clients/" + cDisabled.id()).with(adminUser()))
                .andReturn();
        assertDeleteOk(delOAuth.getResponse().getStatus(), "deleteOAuthClient");
    }

    // -------------------------------------------------------------------------
    // 3. Old /v1/api/clients write endpoints no longer exist as OAuth CRUD
    // -------------------------------------------------------------------------
    @Test
    void existingOAuth2AdminClientEndpointsMovedOffOldClientsPath() throws Exception {
        int s1 = mockMvc.perform(post("/v1/api/clients/create").with(adminUser())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of("scopes", ALL_SCOPES))))
                .andReturn().getResponse().getStatus();
        assertTrue(s1 == 404 || s1 == 405, "POST /v1/api/clients/create must not exist, got " + s1);

        int s2 = mockMvc.perform(post("/v1/api/clients").with(adminUser())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of("scopes", ALL_SCOPES))))
                .andReturn().getResponse().getStatus();
        assertTrue(s2 == 404 || s2 == 405, "POST /v1/api/clients must not exist, got " + s2);

        int s3 = mockMvc.perform(delete("/v1/api/clients/1").with(adminUser())).andReturn().getResponse().getStatus();
        assertTrue(s3 == 404 || s3 == 405, "DELETE /v1/api/clients/{id} must not exist, got " + s3);

        CreatedOAuthClient c = createOAuthClient("authcheck", null, true, ALL_SCOPES);
        String bearer = fetchBearerToken(c);

        MvcResult anonRes = mockMvc.perform(get("/v1/api/oauth-clients/all")).andReturn();
        if (anonRes.getResponse().getStatus() == 404 || anonRes.getResponse().getStatus() == 405) {
            anonRes = mockMvc.perform(get("/v1/api/oauth-clients")).andReturn();
        }
        assertRejected4xx(anonRes.getResponse().getStatus(), "Anonymous on /v1/api/oauth-clients");

        MvcResult userRes = mockMvc.perform(get("/v1/api/oauth-clients/all").with(plainUser())).andReturn();
        if (userRes.getResponse().getStatus() == 404 || userRes.getResponse().getStatus() == 405) {
            userRes = mockMvc.perform(get("/v1/api/oauth-clients").with(plainUser())).andReturn();
        }
        assertRejected4xx(userRes.getResponse().getStatus(), "ROLE_USER on /v1/api/oauth-clients");

        MvcResult bearerRes = mockMvc.perform(get("/v1/api/oauth-clients/all").with(bearerHeader(bearer))).andReturn();
        if (bearerRes.getResponse().getStatus() == 404 || bearerRes.getResponse().getStatus() == 405) {
            bearerRes = mockMvc.perform(get("/v1/api/oauth-clients").with(bearerHeader(bearer))).andReturn();
        }
        assertRejected4xx(bearerRes.getResponse().getStatus(), "Bearer on /v1/api/oauth-clients");
    }

    // -------------------------------------------------------------------------
    // 4. /v1/api/users exposes radiusClients / oauthClients & preserves on PUT omission
    // -------------------------------------------------------------------------
    @Test
    void userEndpointsExposeAssignmentsAndPreserveOnPutOmission() throws Exception {
        deleteAllRadiusClients();
        CreatedOAuthClient oa1 = createOAuthClient("oa-1", null, true, ALL_SCOPES);
        long rc1 = createRadiusClient("rc-1", "127.0.0.1", radiusSecret("u-rc-1"), true, null);

        CreatedUser u = createUserWithToken("assign-user", null, List.of(), List.of());
        putOAuthAssignment(u.id(), oa1.id(), null, AuthMode.PASSWORD_ONLY, false);
        putRadiusAssignment(u.id(), rc1, null, null, false);

        MvcResult getSingle = mockMvc.perform(get("/v1/api/users/" + u.id()).with(adminUser())).andReturn();
        assertEquals(200, getSingle.getResponse().getStatus());
        JsonNode json = JSON.readTree(getSingle.getResponse().getContentAsString());
        assertEquals(1, json.get("oauthClients").size());
        assertEquals(oa1.id(), json.get("oauthClients").get(0).get("clientId").asLong());
        assertTrue(json.get("oauthClients").get(0).get("enabled").asBoolean());
        assertEquals("PASSWORD_ONLY", json.get("oauthClients").get(0).get("authMode").asText());
        assertEquals(1, json.get("radiusClients").size());
        assertEquals(rc1, json.get("radiusClients").get(0).get("clientId").asLong());
        assertTrue(json.get("radiusClients").get(0).get("enabled").asBoolean());

        // Check /v1/api/users/all also includes assignments
        MvcResult getAll = mockMvc.perform(get("/v1/api/users/all").with(adminUser())).andReturn();
        assertEquals(200, getAll.getResponse().getStatus());
        JsonNode foundInAll = findById(JSON.readTree(getAll.getResponse().getContentAsString()), u.id());
        assertNotNull(foundInAll);
        assertEquals(1, foundInAll.get("oauthClients").size());
        assertEquals(1, foundInAll.get("radiusClients").size());

        // PUT /v1/api/users/{id} omitting oauthClients and radiusClients MUST preserve both
        MvcResult putPreserve = mockMvc.perform(put("/v1/api/users/" + u.id()).with(adminUser())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of("username", u.username(), "enabled", true))))
                .andReturn();
        assertEquals(200, putPreserve.getResponse().getStatus());
        JsonNode afterPreserve = JSON.readTree(putPreserve.getResponse().getContentAsString());
        assertEquals(1, afterPreserve.get("oauthClients").size());
        assertEquals(oa1.id(), afterPreserve.get("oauthClients").get(0).get("clientId").asLong());
        assertEquals(1, afterPreserve.get("radiusClients").size());
        assertEquals(rc1, afterPreserve.get("radiusClients").get(0).get("clientId").asLong());

        // Updating and deleting via per-binding endpoints reflects live on GET /v1/api/users/{id}
        putOAuthAssignment(u.id(), oa1.id(), false, AuthMode.OTP_ONLY, false);
        JsonNode afterUpdate = JSON.readTree(mockMvc.perform(get("/v1/api/users/" + u.id()).with(adminUser()))
                .andReturn().getResponse().getContentAsString());
        assertEquals(1, afterUpdate.get("oauthClients").size());
        assertEquals(oa1.id(), afterUpdate.get("oauthClients").get(0).get("clientId").asLong());
        assertFalse(afterUpdate.get("oauthClients").get(0).get("enabled").asBoolean());
        assertEquals("OTP_ONLY", afterUpdate.get("oauthClients").get(0).get("authMode").asText());
        assertEquals(1, afterUpdate.get("radiusClients").size());

        assertDeleteOk(mockMvc.perform(delete("/v1/api/users/" + u.id() + "/oauth-clients/" + oa1.id())
                .with(adminUser())).andReturn().getResponse().getStatus(), "DELETE oauth binding");
        JsonNode afterClear = JSON.readTree(mockMvc.perform(get("/v1/api/users/" + u.id()).with(adminUser()))
                .andReturn().getResponse().getContentAsString());
        assertTrue(!afterClear.has("oauthClients") || afterClear.get("oauthClients").isNull()
                        || afterClear.get("oauthClients").isEmpty(),
                "Deleted OAuth binding must no longer appear in user oauthClients");
        assertEquals(1, afterClear.get("radiusClients").size());
        assertEquals(rc1, afterClear.get("radiusClients").get(0).get("clientId").asLong());
    }

    // -------------------------------------------------------------------------
    // 5. Per-binding endpoints CRUD & ROLE_ADMIN authorization
    // -------------------------------------------------------------------------
    @Test
    void perBindingEndpointsCrudAndAdminOnlyAuthorization() throws Exception {
        deleteAllRadiusClients();
        CreatedOAuthClient oa = createOAuthClient("bind-oa", null, true, ALL_SCOPES);
        long rc = createRadiusClient("bind-rc", "127.0.0.1", radiusSecret("bind-rc-1"), true, null);
        CreatedUser u = createUserWithToken("bind-user", null, List.of(), List.of());

        // OAuth per-binding CRUD
        MvcResult putOa = mockMvc.perform(put("/v1/api/users/" + u.id() + "/oauth-clients/" + oa.id())
                        .with(adminUser())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of("clientId", oa.id()))))
                .andReturn();
        assertSuccess2xx(putOa.getResponse().getStatus(), "PUT oauth binding");
        String putOaBody = putOa.getResponse().getContentAsString();
        JsonNode oaBinding;
        if (putOaBody != null && !putOaBody.isBlank()) {
            oaBinding = JSON.readTree(putOaBody);
        } else {
            MvcResult fetched = mockMvc.perform(get("/v1/api/users/" + u.id() + "/oauth-clients/" + oa.id())
                    .with(adminUser())).andReturn();
            assertEquals(200, fetched.getResponse().getStatus());
            oaBinding = JSON.readTree(fetched.getResponse().getContentAsString());
        }
        assertEquals(oa.id(), oaBinding.get("clientId").asLong());
        assertTrue(oaBinding.get("enabled").asBoolean());

        MvcResult listOa = mockMvc.perform(get("/v1/api/users/" + u.id() + "/oauth-clients").with(adminUser()))
                .andReturn();
        assertEquals(200, listOa.getResponse().getStatus());
        assertEquals(1, JSON.readTree(listOa.getResponse().getContentAsString()).size());

        MvcResult getOneOa = mockMvc.perform(get("/v1/api/users/" + u.id() + "/oauth-clients/" + oa.id())
                        .with(adminUser()))
                .andReturn();
        assertEquals(200, getOneOa.getResponse().getStatus());
        assertEquals(oa.id(), JSON.readTree(getOneOa.getResponse().getContentAsString()).get("clientId").asLong());

        putOAuthAssignment(u.id(), oa.id(), false, AuthMode.OTP_ONLY, false);
        JsonNode updatedOa = JSON.readTree(mockMvc.perform(
                get("/v1/api/users/" + u.id() + "/oauth-clients/" + oa.id()).with(adminUser()))
                .andReturn().getResponse().getContentAsString());
        assertFalse(updatedOa.get("enabled").asBoolean());
        assertEquals("OTP_ONLY", updatedOa.get("authMode").asText());

        // Repeated PUT must be idempotent (no duplicate OAuth binding row)
        MvcResult listOaAfterUpsert = mockMvc.perform(get("/v1/api/users/" + u.id() + "/oauth-clients").with(adminUser()))
                .andReturn();
        assertEquals(200, listOaAfterUpsert.getResponse().getStatus());
        assertEquals(1, JSON.readTree(listOaAfterUpsert.getResponse().getContentAsString()).size());

        // RADIUS per-binding CRUD
        MvcResult putRc = mockMvc.perform(put("/v1/api/users/" + u.id() + "/radius-clients/" + rc)
                        .with(adminUser())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of("clientId", rc))))
                .andReturn();
        assertSuccess2xx(putRc.getResponse().getStatus(), "PUT radius binding");
        String putRcBody = putRc.getResponse().getContentAsString();
        JsonNode rcBinding;
        if (putRcBody != null && !putRcBody.isBlank()) {
            rcBinding = JSON.readTree(putRcBody);
        } else {
            MvcResult fetched = mockMvc.perform(get("/v1/api/users/" + u.id() + "/radius-clients/" + rc)
                    .with(adminUser())).andReturn();
            assertEquals(200, fetched.getResponse().getStatus());
            rcBinding = JSON.readTree(fetched.getResponse().getContentAsString());
        }
        assertEquals(rc, rcBinding.get("clientId").asLong());
        assertTrue(rcBinding.get("enabled").asBoolean());

        putRadiusAssignment(u.id(), rc, false, AuthMode.PASSWORD_ONLY, false);
        JsonNode updatedRc = JSON.readTree(mockMvc.perform(
                get("/v1/api/users/" + u.id() + "/radius-clients/" + rc).with(adminUser()))
                .andReturn().getResponse().getContentAsString());
        assertFalse(updatedRc.get("enabled").asBoolean());
        assertEquals("PASSWORD_ONLY", updatedRc.get("authMode").asText());

        // Repeated PUT must be idempotent (no duplicate RADIUS binding row)
        MvcResult listRcAfterUpsert = mockMvc.perform(get("/v1/api/users/" + u.id() + "/radius-clients").with(adminUser()))
                .andReturn();
        assertEquals(200, listRcAfterUpsert.getResponse().getStatus());
        assertEquals(1, JSON.readTree(listRcAfterUpsert.getResponse().getContentAsString()).size());

        // Multi-user isolation: second user's enabled bindings remain separate from first user
        CreatedUser u2 = createUserWithToken("bind-user-2", null, List.of(), List.of());
        putOAuthAssignment(u2.id(), oa.id(), true, null, false);
        putRadiusAssignment(u2.id(), rc, true, null, false);

        MvcResult u2OaListRes = mockMvc.perform(get("/v1/api/users/" + u2.id() + "/oauth-clients").with(adminUser()))
                .andReturn();
        assertEquals(200, u2OaListRes.getResponse().getStatus());
        JsonNode u2OaList = JSON.readTree(u2OaListRes.getResponse().getContentAsString());
        assertEquals(1, u2OaList.size());
        assertTrue(u2OaList.get(0).get("enabled").asBoolean());

        MvcResult u2RcListRes = mockMvc.perform(get("/v1/api/users/" + u2.id() + "/radius-clients").with(adminUser()))
                .andReturn();
        assertEquals(200, u2RcListRes.getResponse().getStatus());
        JsonNode u2RcList = JSON.readTree(u2RcListRes.getResponse().getContentAsString());
        assertEquals(1, u2RcList.size());
        assertTrue(u2RcList.get(0).get("enabled").asBoolean());

        // Delete both for u & confirm 404, while u2's bindings stay intact
        assertDeleteOk(mockMvc.perform(delete("/v1/api/users/" + u.id() + "/oauth-clients/" + oa.id())
                .with(adminUser())).andReturn().getResponse().getStatus(), "DELETE oauth binding");
        assertEquals(404, mockMvc.perform(get("/v1/api/users/" + u.id() + "/oauth-clients/" + oa.id())
                .with(adminUser())).andReturn().getResponse().getStatus());

        assertDeleteOk(mockMvc.perform(delete("/v1/api/users/" + u.id() + "/radius-clients/" + rc)
                .with(adminUser())).andReturn().getResponse().getStatus(), "DELETE radius binding");
        assertEquals(404, mockMvc.perform(get("/v1/api/users/" + u.id() + "/radius-clients/" + rc)
                .with(adminUser())).andReturn().getResponse().getStatus());

        MvcResult u2OaStillPresent = mockMvc.perform(
                get("/v1/api/users/" + u2.id() + "/oauth-clients/" + oa.id()).with(adminUser())).andReturn();
        assertEquals(200, u2OaStillPresent.getResponse().getStatus());
        assertTrue(JSON.readTree(u2OaStillPresent.getResponse().getContentAsString()).get("enabled").asBoolean());

        MvcResult u2RcStillPresent = mockMvc.perform(
                get("/v1/api/users/" + u2.id() + "/radius-clients/" + rc).with(adminUser())).andReturn();
        assertEquals(200, u2RcStillPresent.getResponse().getStatus());
        assertTrue(JSON.readTree(u2RcStillPresent.getResponse().getContentAsString()).get("enabled").asBoolean());

        // Non-existent user or client -> 4xx (not 405, never 500)
        int missingUserStatus = mockMvc.perform(put("/v1/api/users/999999/oauth-clients/" + oa.id())
                        .with(adminUser()).contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of("clientId", oa.id()))))
                .andReturn().getResponse().getStatus();
        assertTrue(missingUserStatus >= 400 && missingUserStatus < 500 && missingUserStatus != 405,
                "Expected 4xx (not 405) for missing user, got " + missingUserStatus);

        int missingClientStatus = mockMvc.perform(put("/v1/api/users/" + u.id() + "/oauth-clients/999999")
                        .with(adminUser()).contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of("clientId", 999999L))))
                .andReturn().getResponse().getStatus();
        assertTrue(missingClientStatus >= 400 && missingClientStatus < 500 && missingClientStatus != 405,
                "Expected 4xx (not 405) for missing client, got " + missingClientStatus);

        // Authorization checks: anonymous, ROLE_USER, Bearer -> 4xx (not 404/405)
        String bearer = fetchBearerToken(oa);
        for (String path : List.of(
                "/v1/api/users/" + u.id() + "/oauth-clients",
                "/v1/api/users/" + u.id() + "/radius-clients")) {
            assertRejected4xx(mockMvc.perform(get(path)).andReturn().getResponse().getStatus(),
                    "Anonymous on " + path);
            assertRejected4xx(mockMvc.perform(get(path).with(plainUser())).andReturn().getResponse().getStatus(),
                    "ROLE_USER on " + path);
            assertRejected4xx(mockMvc.perform(get(path).with(bearerHeader(bearer)))
                    .andReturn().getResponse().getStatus(), "Bearer on " + path);
        }
    }

    // -------------------------------------------------------------------------
    // 6. OAuth login enforces enabled assignment and isolates clients
    // -------------------------------------------------------------------------
    @Test
    void oauthLoginRequiresEnabledAssignmentAndIsolatesClients() throws Exception {
        CreatedOAuthClient oa = createOAuthClient("app-a", AuthMode.PASSWORD_ONLY, true, ALL_SCOPES);
        CreatedOAuthClient ob = createOAuthClient("app-b", AuthMode.PASSWORD_ONLY, true, ALL_SCOPES);
        String bearerA = fetchBearerToken(oa);
        String bearerB = fetchBearerToken(ob);

        CreatedUser u = createUserWithToken("portal-user", null,
                List.of(binding(oa.id(), true, null)), List.of());

        // Assigned A succeeds
        MvcResult resA = mockMvc.perform(post("/v1/api/auth/login").with(bearerHeader(bearerA))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of("username", u.username(), "password", USER_PASS))))
                .andReturn();
        assertEquals(200, resA.getResponse().getStatus());
        assertTrue(JSON.readTree(resA.getResponse().getContentAsString()).get("authenticated").asBoolean());

        // Unassigned B denied
        MvcResult resB = mockMvc.perform(post("/v1/api/auth/login").with(bearerHeader(bearerB))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of("username", u.username(), "password", USER_PASS))))
                .andReturn();
        assertRejected4xx(resB.getResponse().getStatus(), "Unassigned OAuth login");
        assertJsonFieldNotTrue(resB, "authenticated");

        // Disable A -> denied
        putOAuthAssignment(u.id(), oa.id(), false, null, false);
        MvcResult resDisabled = mockMvc.perform(post("/v1/api/auth/login").with(bearerHeader(bearerA))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of("username", u.username(), "password", USER_PASS))))
                .andReturn();
        assertRejected4xx(resDisabled.getResponse().getStatus(), "Disabled OAuth login");
        assertJsonFieldNotTrue(resDisabled, "authenticated");

        // Re-enable A -> succeeds again
        putOAuthAssignment(u.id(), oa.id(), true, null, false);
        MvcResult resReenabled = mockMvc.perform(post("/v1/api/auth/login").with(bearerHeader(bearerA))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of("username", u.username(), "password", USER_PASS))))
                .andReturn();
        assertEquals(200, resReenabled.getResponse().getStatus());
        assertTrue(JSON.readTree(resReenabled.getResponse().getContentAsString()).get("authenticated").asBoolean());

        // Delete A assignment -> immediate runtime denial
        assertDeleteOk(mockMvc.perform(delete("/v1/api/users/" + u.id() + "/oauth-clients/" + oa.id())
                .with(adminUser())).andReturn().getResponse().getStatus(), "DELETE OAuth assignment");
        MvcResult resDeleted = mockMvc.perform(post("/v1/api/auth/login").with(bearerHeader(bearerA))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of("username", u.username(), "password", USER_PASS))))
                .andReturn();
        assertRejected4xx(resDeleted.getResponse().getStatus(), "Deleted OAuth assignment login");
        assertJsonFieldNotTrue(resDeleted, "authenticated");
    }

    // -------------------------------------------------------------------------
    // 7. /otp/validate, /otp/validate-ocra, /mfa/preauth enforce assignment without burning OTP/state
    // -------------------------------------------------------------------------
    @Test
    void oauthOtpValidateOcraAndMfaPreauthEnforceEnabledAssignment() throws Exception {
        CreatedOAuthClient oa = createOAuthClient("otp-a", null, true, ALL_SCOPES);
        CreatedOAuthClient ob = createOAuthClient("otp-b", null, true, ALL_SCOPES);
        String bearerA = fetchBearerToken(oa);
        String bearerB = fetchBearerToken(ob);

        long step = stableCurrentStep();
        String secret = distinctSecret(step);
        CreatedUser u = createUserWithToken("otp-bound-user", secret,
                List.of(binding(oa.id(), true, null)), List.of());

        String totpForValidate = otpForStep(secret, step - 1);
        String totpForPreauth = otpForStep(secret, step + 1);
        String challenge = "CHAL" + uniqueSuffix().toUpperCase(Locale.ROOT);
        String ocraOtp = ocraService.generateOcra(secret, challenge);

        // 1) TOTP /v1/api/otp/validate rejected on unassigned B without burning totpForValidate
        MvcResult valB = mockMvc.perform(post("/v1/api/otp/validate").with(bearerHeader(bearerB))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of("username", u.username(), "otp", totpForValidate))))
                .andReturn();
        assertRejected4xx(valB.getResponse().getStatus(), "Unassigned /otp/validate");
        assertJsonFieldNotTrue(valB, "valid");

        // Disable A -> rejected without burning totpForValidate
        putOAuthAssignment(u.id(), oa.id(), false, null, false);
        MvcResult valDisabled = mockMvc.perform(post("/v1/api/otp/validate").with(bearerHeader(bearerA))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of("username", u.username(), "otp", totpForValidate))))
                .andReturn();
        assertRejected4xx(valDisabled.getResponse().getStatus(), "Disabled /otp/validate");
        assertJsonFieldNotTrue(valDisabled, "valid");

        // Re-enable A -> SAME totpForValidate succeeds
        putOAuthAssignment(u.id(), oa.id(), true, null, false);
        MvcResult valA = mockMvc.perform(post("/v1/api/otp/validate").with(bearerHeader(bearerA))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of("username", u.username(), "otp", totpForValidate))))
                .andReturn();
        assertEquals(200, valA.getResponse().getStatus());
        assertTrue(JSON.readTree(valA.getResponse().getContentAsString()).get("valid").asBoolean());

        // 2) OCRA /v1/api/otp/validate-ocra rejected on unassigned B and disabled A without burning challenge/OTP
        MvcResult ocraB = mockMvc.perform(post("/v1/api/otp/validate-ocra").with(bearerHeader(bearerB))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of(
                                "username", u.username(), "challenge", challenge, "otp", ocraOtp))))
                .andReturn();
        assertRejected4xx(ocraB.getResponse().getStatus(), "Unassigned /otp/validate-ocra");
        assertJsonFieldNotTrue(ocraB, "valid");

        putOAuthAssignment(u.id(), oa.id(), false, null, false);
        MvcResult ocraDisabled = mockMvc.perform(post("/v1/api/otp/validate-ocra").with(bearerHeader(bearerA))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of(
                                "username", u.username(), "challenge", challenge, "otp", ocraOtp))))
                .andReturn();
        assertRejected4xx(ocraDisabled.getResponse().getStatus(), "Disabled /otp/validate-ocra");
        assertJsonFieldNotTrue(ocraDisabled, "valid");

        putOAuthAssignment(u.id(), oa.id(), true, null, false);
        MvcResult ocraA = mockMvc.perform(post("/v1/api/otp/validate-ocra").with(bearerHeader(bearerA))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of(
                                "username", u.username(), "challenge", challenge, "otp", ocraOtp))))
                .andReturn();
        assertEquals(200, ocraA.getResponse().getStatus());
        assertTrue(JSON.readTree(ocraA.getResponse().getContentAsString()).get("valid").asBoolean());

        // 3) MFA Pre-Auth /v1/api/mfa/preauth rejected on unassigned B and disabled A without creating approval or burning OTP
        MvcResult preB = mockMvc.perform(post("/v1/api/mfa/preauth").with(bearerHeader(bearerB))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of(
                                "username", u.username(), "otp", Integer.parseInt(totpForPreauth)))))
                .andReturn();
        int preBStatus = preB.getResponse().getStatus();
        String preBBody = preB.getResponse().getContentAsString().trim();
        assertTrue((preBStatus >= 400 && preBStatus < 500 && preBStatus != 404 && preBStatus != 405)
                        || (preBStatus == 200 && "false".equalsIgnoreCase(preBBody)),
                "Unassigned /mfa/preauth must be denied (4xx) or return false, got " + preBStatus + " body=" + preBBody);
        assertTrue(approvalRepository.findByUserId(u.id()).isEmpty(),
                "Denied /mfa/preauth must not create an MfaApproval");

        putOAuthAssignment(u.id(), oa.id(), false, null, false);
        MvcResult preDisabled = mockMvc.perform(post("/v1/api/mfa/preauth").with(bearerHeader(bearerA))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of(
                                "username", u.username(), "otp", Integer.parseInt(totpForPreauth)))))
                .andReturn();
        int preDisabledStatus = preDisabled.getResponse().getStatus();
        String preDisabledBody = preDisabled.getResponse().getContentAsString().trim();
        assertTrue((preDisabledStatus >= 400 && preDisabledStatus < 500 && preDisabledStatus != 404 && preDisabledStatus != 405)
                        || (preDisabledStatus == 200 && "false".equalsIgnoreCase(preDisabledBody)),
                "Disabled /mfa/preauth must be denied (4xx) or return false, got " + preDisabledStatus + " body=" + preDisabledBody);
        assertTrue(approvalRepository.findByUserId(u.id()).isEmpty(),
                "Disabled /mfa/preauth must not create an MfaApproval");

        putOAuthAssignment(u.id(), oa.id(), true, null, false);
        MvcResult preA = mockMvc.perform(post("/v1/api/mfa/preauth").with(bearerHeader(bearerA))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of(
                                "username", u.username(), "otp", Integer.parseInt(totpForPreauth)))))
                .andReturn();
        assertEquals(200, preA.getResponse().getStatus());
        assertEquals("true", preA.getResponse().getContentAsString().trim());
        assertFalse(approvalRepository.findByUserId(u.id()).isEmpty());
    }

    // -------------------------------------------------------------------------
    // 8. OAuth AuthMode precedence: Assignment > Client > SecurityPolicy
    // -------------------------------------------------------------------------
    @Test
    void oauthAuthModePrecedenceAssignmentOverridesClientOverridesPolicy() throws Exception {
        configurePolicy(AuthMode.PASSWORD_AND_OTP, 5);
        CreatedOAuthClient clientA = createOAuthClient("mode-a", AuthMode.PASSWORD_ONLY, true, ALL_SCOPES);
        CreatedOAuthClient clientB = createOAuthClient("mode-b", null, true, ALL_SCOPES);
        String bearerA = fetchBearerToken(clientA);
        String bearerB = fetchBearerToken(clientB);

        long step = stableCurrentStep();
        String secret = distinctSecret(step);
        CreatedUser u = createUserWithToken("mode-user", secret,
                List.of(
                        binding(clientA.id(), true, AuthMode.OTP_ONLY),
                        binding(clientB.id(), true, null)),
                List.of());

        // 1) Assignment OTP_ONLY on Client A overrides Client A PASSWORD_ONLY
        String otp = otpForStep(secret, step);
        MvcResult otpOnlyRes = mockMvc.perform(post("/v1/api/auth/login").with(bearerHeader(bearerA))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of("username", u.username(), "otp", otp))))
                .andReturn();
        assertEquals(200, otpOnlyRes.getResponse().getStatus());
        assertTrue(JSON.readTree(otpOnlyRes.getResponse().getContentAsString()).get("authenticated").asBoolean());

        // 2) Clear assignment authMode to null on Client A -> falls back to Client A PASSWORD_ONLY
        putOAuthAssignment(u.id(), clientA.id(), true, null, true);
        MvcResult pwOnlyRes = mockMvc.perform(post("/v1/api/auth/login").with(bearerHeader(bearerA))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of("username", u.username(), "password", USER_PASS))))
                .andReturn();
        assertEquals(200, pwOnlyRes.getResponse().getStatus());
        assertTrue(JSON.readTree(pwOnlyRes.getResponse().getContentAsString()).get("authenticated").asBoolean());

        // 3) Assignment authMode null + Client B authMode null -> falls back to SecurityPolicy PASSWORD_AND_OTP
        MvcResult needOtpRes = mockMvc.perform(post("/v1/api/auth/login").with(bearerHeader(bearerB))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of("username", u.username(), "password", USER_PASS))))
                .andReturn();
        assertRejected4xx(needOtpRes.getResponse().getStatus(), "Policy PASSWORD_AND_OTP OTP_REQUIRED fallback");
        JsonNode needOtpJson = JSON.readTree(needOtpRes.getResponse().getContentAsString());
        assertFalse(needOtpJson.path("authenticated").asBoolean());
        assertEquals("OTP_REQUIRED", needOtpJson.path("status").asText());
    }

    // -------------------------------------------------------------------------
    // 9. Denied OAuth login must NOT enroll unenrolled user or leak secret
    // -------------------------------------------------------------------------
    @Test
    void deniedOauthLoginDoesNotEnrollUnenrolledUserOrLeakSecret() throws Exception {
        CreatedOAuthClient unassignedClient = createOAuthClient("unenrolled-deny", AuthMode.PASSWORD_AND_OTP, true, ALL_SCOPES);
        String bearer = fetchBearerToken(unassignedClient);

        CreatedUser u = createUserWithToken("no-token-user", null, List.of(), List.of());

        MvcResult res = mockMvc.perform(post("/v1/api/auth/login").with(bearerHeader(bearer))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of("username", u.username(), "password", USER_PASS))))
                .andReturn();
        assertRejected4xx(res.getResponse().getStatus(), "Denied login of unenrolled user");
        assertJsonFieldNotTrue(res, "authenticated");
        String body = res.getResponse().getContentAsString();
        if (body != null && !body.isBlank()) {
            JsonNode json = JSON.readTree(body);
            assertTrue(json.path("secret").isMissingNode() || json.path("secret").isNull());
            assertTrue(json.path("otpAuthUri").isMissingNode() || json.path("otpAuthUri").isNull());
            assertTrue(json.path("qrCode").isMissingNode() || json.path("qrCode").isNull());
        }

        User reloaded = userRepository.findById(u.id()).orElseThrow();
        assertNull(reloaded.getOtpToken(), "Denied login must NOT enroll an OtpToken");
    }

    // -------------------------------------------------------------------------
    // 10. RADIUS in-band 2-step enforces assignment and isolates 2 NAS clients
    // -------------------------------------------------------------------------
    @Test
    void radiusInBandTwoStepEnforcesAssignmentAndIsolatesTwoNasClients() throws Exception {
        deleteAllRadiusClients();
        String radSecret1 = radiusSecret("nas1");
        String radSecret2 = radiusSecret("nas2");
        long nas1 = createRadiusClient("nas-1", "127.0.0.1", radSecret1, true, AuthMode.PASSWORD_AND_OTP);
        createRadiusClient("nas-2", "127.0.0.2", radSecret2, true, AuthMode.PASSWORD_AND_OTP);

        long step = stableCurrentStep();
        String secret = distinctSecret(step);
        CreatedUser u = createUserWithToken("rad-2step", secret, List.of(),
                List.of(binding(nas1, true, null)));

        // NAS-2 (unassigned) -> immediate Access-Reject (never Access-Challenge)
        byte[] reqAuthUnassigned = randomAuthenticator();
        byte[] pktUnassigned = buildAccessRequest(10, reqAuthUnassigned, u.username(), USER_PASS, null, radSecret2);
        byte[] respUnassigned = sendRadiusPacket("127.0.0.2", pktUnassigned, 2000);
        assertNotNull(respUnassigned, "RADIUS server must reply to configured NAS-2");
        assertEquals(3, respUnassigned[0] & 0xFF, "Unassigned NAS must receive immediate Access-Reject (Code 3)");
        assertValidResponseAuthenticator(respUnassigned, reqAuthUnassigned, radSecret2);

        // NAS-1 (assigned) -> Access-Challenge -> TOTP -> Access-Accept
        byte[] reqAuth1 = randomAuthenticator();
        byte[] pkt1 = buildAccessRequest(11, reqAuth1, u.username(), USER_PASS, null, radSecret1);
        byte[] resp1 = sendRadiusPacket("127.0.0.1", pkt1, 2000);
        assertNotNull(resp1);
        assertEquals(11, resp1[0] & 0xFF, "Assigned NAS must receive Access-Challenge (Code 11)");
        assertValidResponseAuthenticator(resp1, reqAuth1, radSecret1);

        byte[] state = extractAttribute(resp1, 24);
        assertNotNull(state);

        String otp = otpForStep(secret, step);
        byte[] reqAuth2 = randomAuthenticator();
        byte[] pkt2 = buildAccessRequest(12, reqAuth2, u.username(), otp, state, radSecret1);
        byte[] resp2 = sendRadiusPacket("127.0.0.1", pkt2, 2000);
        assertNotNull(resp2);
        assertEquals(2, resp2[0] & 0xFF, "Assigned NAS Turn 2 must receive Access-Accept (Code 2)");
        assertValidResponseAuthenticator(resp2, reqAuth2, radSecret1);

        // Disable NAS-1 assignment -> immediate Access-Reject
        putRadiusAssignment(u.id(), nas1, false, null, false);
        byte[] reqAuth3 = randomAuthenticator();
        byte[] pkt3 = buildAccessRequest(13, reqAuth3, u.username(), USER_PASS, null, radSecret1);
        byte[] resp3 = sendRadiusPacket("127.0.0.1", pkt3, 2000);
        assertNotNull(resp3);
        assertEquals(3, resp3[0] & 0xFF, "Disabled NAS binding must return Access-Reject (Code 3)");
        assertValidResponseAuthenticator(resp3, reqAuth3, radSecret1);

        // Re-enable NAS-1 -> Turn 1 returns Access-Challenge again, then DELETE -> immediate Access-Reject
        putRadiusAssignment(u.id(), nas1, true, null, false);
        byte[] reqAuth4 = randomAuthenticator();
        byte[] pkt4 = buildAccessRequest(14, reqAuth4, u.username(), USER_PASS, null, radSecret1);
        byte[] resp4 = sendRadiusPacket("127.0.0.1", pkt4, 2000);
        assertNotNull(resp4);
        assertEquals(11, resp4[0] & 0xFF, "Re-enabled NAS must issue Access-Challenge (Code 11)");
        assertValidResponseAuthenticator(resp4, reqAuth4, radSecret1);

        assertDeleteOk(mockMvc.perform(delete("/v1/api/users/" + u.id() + "/radius-clients/" + nas1)
                .with(adminUser())).andReturn().getResponse().getStatus(), "DELETE RADIUS assignment");
        byte[] reqAuth5 = randomAuthenticator();
        byte[] pkt5 = buildAccessRequest(15, reqAuth5, u.username(), USER_PASS, null, radSecret1);
        byte[] resp5 = sendRadiusPacket("127.0.0.1", pkt5, 2000);
        assertNotNull(resp5);
        assertEquals(3, resp5[0] & 0xFF, "Deleted NAS binding must immediately return Access-Reject (Code 3)");
        assertValidResponseAuthenticator(resp5, reqAuth5, radSecret1);
    }

    // -------------------------------------------------------------------------
    // 11. RADIUS AuthMode precedence & all remaining flows (PASSWORD_ONLY, OTP_ONLY, INLINE, OOB)
    // -------------------------------------------------------------------------
    @Test
    void radiusAuthModePrecedenceAndRemainingFlowsEnforceAssignment() throws Exception {
        deleteAllRadiusClients();
        String radSecret1 = radiusSecret("flow1");
        String radSecret2 = radiusSecret("flow2");
        long nas1 = createRadiusClient("rad-flow-1", "127.0.0.1", radSecret1, true, AuthMode.PASSWORD_ONLY);
        createRadiusClient("rad-flow-2", "127.0.0.2", radSecret2, true, AuthMode.PASSWORD_ONLY);

        CreatedOAuthClient oauthForPreauth = createOAuthClient("rdg-preauth", null, true, ALL_SCOPES);
        String bearer = fetchBearerToken(oauthForPreauth);

        // 1) Assignment OTP_ONLY overrides NAS-1 PASSWORD_ONLY; rejected NAS-2 does NOT burn OTP
        long step1 = stableCurrentStep();
        String sec1 = distinctSecret(step1);
        CreatedUser otpUser = createUserWithToken("rad-otp-user", sec1,
                List.of(binding(oauthForPreauth.id(), true, null)),
                List.of(binding(nas1, true, AuthMode.OTP_ONLY)));
        String otp1 = otpForStep(sec1, step1);

        byte[] rAuthUnassigned = randomAuthenticator();
        byte[] rUnassigned = sendRadiusPacket("127.0.0.2",
                buildAccessRequest(20, rAuthUnassigned, otpUser.username(), otp1, null, radSecret2), 2000);
        assertNotNull(rUnassigned);
        assertEquals(3, rUnassigned[0] & 0xFF);
        assertValidResponseAuthenticator(rUnassigned, rAuthUnassigned, radSecret2);

        byte[] rAuthOtp = randomAuthenticator();
        byte[] rOtp = sendRadiusPacket("127.0.0.1",
                buildAccessRequest(21, rAuthOtp, otpUser.username(), otp1, null, radSecret1), 2000);
        assertNotNull(rOtp);
        assertEquals(2, rOtp[0] & 0xFF, "OTP_ONLY assignment must override client PASSWORD_ONLY and preserve OTP");
        assertValidResponseAuthenticator(rOtp, rAuthOtp, radSecret1);

        // 2) PASSWORD_AND_OTP_INLINE on assignment overrides NAS-1 PASSWORD_ONLY
        long step2 = stableCurrentStep();
        String sec2 = distinctSecret(step2);
        CreatedUser inlineUser = createUserWithToken("rad-inline-user", sec2, List.of(),
                List.of(binding(nas1, true, AuthMode.PASSWORD_AND_OTP_INLINE)));
        String otp2 = otpForStep(sec2, step2);

        // Sending password without inline OTP must reject
        byte[] rAuthInlineNoOtp = randomAuthenticator();
        byte[] rInlineNoOtp = sendRadiusPacket("127.0.0.1",
                buildAccessRequest(22, rAuthInlineNoOtp, inlineUser.username(), USER_PASS, null, radSecret1), 2000);
        assertNotNull(rInlineNoOtp);
        assertEquals(3, rInlineNoOtp[0] & 0xFF);
        assertValidResponseAuthenticator(rInlineNoOtp, rAuthInlineNoOtp, radSecret1);

        // Sending password + inline OTP must accept
        byte[] rAuthInlineOk = randomAuthenticator();
        byte[] rInlineOk = sendRadiusPacket("127.0.0.1",
                buildAccessRequest(23, rAuthInlineOk, inlineUser.username(), USER_PASS + otp2, null, radSecret1), 2000);
        assertNotNull(rInlineOk);
        assertEquals(2, rInlineOk[0] & 0xFF);
        assertValidResponseAuthenticator(rInlineOk, rAuthInlineOk, radSecret1);

        // 3) Clear assignment authMode -> falls back to NAS-1 PASSWORD_ONLY
        putRadiusAssignment(inlineUser.id(), nas1, true, null, true);
        byte[] rAuthPwFallback = randomAuthenticator();
        byte[] rPwFallback = sendRadiusPacket("127.0.0.1",
                buildAccessRequest(24, rAuthPwFallback, inlineUser.username(), USER_PASS, null, radSecret1), 2000);
        assertNotNull(rPwFallback);
        assertEquals(2, rPwFallback[0] & 0xFF);
        assertValidResponseAuthenticator(rPwFallback, rAuthPwFallback, radSecret1);

        // 4) Out-of-band RDG (no User-Password): unassigned NAS-2 rejects without consuming approval; NAS-1 accepts
        long step3 = stableCurrentStep();
        String sec3 = distinctSecret(step3);
        CreatedUser oobUser = createUserWithToken("rad-oob-user", sec3,
                List.of(binding(oauthForPreauth.id(), true, null)),
                List.of(binding(nas1, true, null)));
        String otp3 = otpForStep(sec3, step3);

        MvcResult pre = mockMvc.perform(post("/v1/api/mfa/preauth").with(bearerHeader(bearer))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of(
                                "username", oobUser.username(), "otp", Integer.parseInt(otp3)))))
                .andReturn();
        assertEquals(200, pre.getResponse().getStatus());
        assertEquals("true", pre.getResponse().getContentAsString().trim());

        // Unassigned NAS-2 without User-Password -> Access-Reject and approval still intact
        byte[] rAuthOobDeny = randomAuthenticator();
        byte[] rOobDeny = sendRadiusPacket("127.0.0.2",
                buildAccessRequest(25, rAuthOobDeny, oobUser.username(), null, null, radSecret2), 2000);
        assertNotNull(rOobDeny);
        assertEquals(3, rOobDeny[0] & 0xFF);
        assertValidResponseAuthenticator(rOobDeny, rAuthOobDeny, radSecret2);
        assertFalse(approvalRepository.findByUserId(oobUser.id()).isEmpty(),
                "Denied OOB RADIUS request must NOT consume MfaApproval");

        // Assigned NAS-1 without User-Password -> Access-Accept
        byte[] rAuthOobAccept = randomAuthenticator();
        byte[] rOobAccept = sendRadiusPacket("127.0.0.1",
                buildAccessRequest(26, rAuthOobAccept, oobUser.username(), null, null, radSecret1), 2000);
        assertNotNull(rOobAccept);
        assertEquals(2, rOobAccept[0] & 0xFF);
        assertValidResponseAuthenticator(rOobAccept, rAuthOobAccept, radSecret1);
    }

    // -------------------------------------------------------------------------
    // 12. Revoking NAS-1 assignment invalidates/rejects its pending challenge & leaves NAS-2 usable
    // -------------------------------------------------------------------------
    @Test
    void radiusRevocationInvalidatesPendingChallengeAndLeavesOtherClientUsable() throws Exception {
        deleteAllRadiusClients();
        String radSecret1 = radiusSecret("rev1");
        String radSecret2 = radiusSecret("rev2");
        long nas1 = createRadiusClient("rev-nas-1", "127.0.0.1", radSecret1, true, AuthMode.PASSWORD_AND_OTP);
        createRadiusClient("rev-nas-2", "127.0.0.2", radSecret2, true, AuthMode.PASSWORD_AND_OTP);

        long step = stableCurrentStep();
        String secret = distinctSecret(step);
        CreatedUser u = createUserWithToken("rev-user", secret, List.of(),
                List.of(binding(nas1, true, null), binding(findRadiusClientIdByNamePrefix("rev-nas-2"), true, null)));

        // Start Turn 1 on NAS-1
        byte[] reqAuth1 = randomAuthenticator();
        byte[] resp1Nas1 = sendRadiusPacket("127.0.0.1",
                buildAccessRequest(31, reqAuth1, u.username(), USER_PASS, null, radSecret1), 2000);
        assertNotNull(resp1Nas1);
        assertEquals(11, resp1Nas1[0] & 0xFF);
        assertValidResponseAuthenticator(resp1Nas1, reqAuth1, radSecret1);
        byte[] state1 = extractAttribute(resp1Nas1, 24);
        assertNotNull(state1);

        // Revoke ONLY NAS-1 assignment
        putRadiusAssignment(u.id(), nas1, false, null, false);

        String otpRevokedNas = otpForStep(secret, step - 1);
        String otpIntactNas = otpForStep(secret, step + 1);

        // Turn 2 on revoked NAS-1 with state1 must reject
        byte[] reqAuthRevoked = randomAuthenticator();
        byte[] resp2Nas1 = sendRadiusPacket("127.0.0.1",
                buildAccessRequest(32, reqAuthRevoked, u.username(), otpRevokedNas, state1, radSecret1), 2000);
        assertNotNull(resp2Nas1);
        assertEquals(3, resp2Nas1[0] & 0xFF, "Turn 2 on revoked NAS-1 must return Access-Reject");
        assertValidResponseAuthenticator(resp2Nas1, reqAuthRevoked, radSecret1);

        // Fresh 2-step Turn 1 -> Access-Challenge -> Turn 2 on unaffected NAS-2 must succeed
        byte[] reqAuthNas2Turn1 = randomAuthenticator();
        byte[] resp1Nas2 = sendRadiusPacket("127.0.0.2",
                buildAccessRequest(33, reqAuthNas2Turn1, u.username(), USER_PASS, null, radSecret2), 2000);
        assertNotNull(resp1Nas2);
        assertEquals(11, resp1Nas2[0] & 0xFF, "Turn 1 on unaffected NAS-2 must issue Access-Challenge");
        assertValidResponseAuthenticator(resp1Nas2, reqAuthNas2Turn1, radSecret2);
        byte[] state2 = extractAttribute(resp1Nas2, 24);
        assertNotNull(state2);

        byte[] reqAuthNas2Turn2 = randomAuthenticator();
        byte[] resp2Nas2 = sendRadiusPacket("127.0.0.2",
                buildAccessRequest(34, reqAuthNas2Turn2, u.username(), otpIntactNas, state2, radSecret2), 2000);
        assertNotNull(resp2Nas2);
        assertEquals(2, resp2Nas2[0] & 0xFF, "Turn 2 on unaffected NAS-2 must still succeed");
        assertValidResponseAuthenticator(resp2Nas2, reqAuthNas2Turn2, radSecret2);
    }

    private long findRadiusClientIdByNamePrefix(String prefix) throws Exception {
        MvcResult list = mockMvc.perform(get("/v1/api/radius-clients/all").with(adminUser())).andReturn();
        assertEquals(200, list.getResponse().getStatus());
        for (JsonNode c : JSON.readTree(list.getResponse().getContentAsString())) {
            if (c.path("name").asText("").startsWith(prefix)) {
                return c.get("id").asLong();
            }
        }
        throw new IllegalStateException("RadiusClient not found with prefix " + prefix);
    }

    // -------------------------------------------------------------------------
    // 13. LDAP autoProvision auto-assigns new user ONLY to calling OAuthClient
    // -------------------------------------------------------------------------
    @Test
    void ldapAutoProvisionAssignsNewUserOnlyToCallingOAuthClient() throws Exception {
        deleteAllRadiusClients();
        String radSec = radiusSecret("ldap1");
        CreatedOAuthClient oauthA = createOAuthClient("ldap-pw-client", AuthMode.PASSWORD_ONLY, true, ALL_SCOPES);
        CreatedOAuthClient oauthB = createOAuthClient("ldap-other-client", AuthMode.PASSWORD_ONLY, true, ALL_SCOPES);
        CreatedOAuthClient oauthC = createOAuthClient("ldap-mfa-client", AuthMode.PASSWORD_AND_OTP, true, ALL_SCOPES);
        long radId = createRadiusClient("ldap-nas", "127.0.0.1", radSec, true, AuthMode.PASSWORD_ONLY);

        String bearerA = fetchBearerToken(oauthA);
        String bearerB = fetchBearerToken(oauthB);
        String bearerC = fetchBearerToken(oauthC);

        String aliceName = "ldapalice" + uniqueSuffix();
        String bobName = "ldapbob" + uniqueSuffix();
        String charlieName = "ldapcharlie" + uniqueSuffix();
        Map<String, String> ldapUsers = Map.of(aliceName, USER_PASS, bobName, USER_PASS, charlieName, USER_PASS);

        try (TestLdapServer ldapServer = new TestLdapServer(ldapUsers)) {
            LdapDirectory dir = LdapDirectory.builder()
                    .name("grader-ldap-" + uniqueSuffix())
                    .enabled(true)
                    .userEnabled(true)
                    .adminEnabled(false)
                    .priority(1)
                    .url("ldap://127.0.0.1:" + ldapServer.getPort())
                    .baseDn("dc=example,dc=org")
                    .userSearchFilter("(&(objectClass=person)(|(uid={0})(sAMAccountName={0})))")
                    .bindDn("cn=admin,dc=example,dc=org")
                    .bindPassword(LDAP_BIND_PASSWORD)
                    .autoProvision(true)
                    .fallbackToLocal(false)
                    .build();
            ldapDirectoryRepository.saveAndFlush(dir);

            // Branch 1: PASSWORD_ONLY calling client -> AUTHENTICATED & assigned ONLY to oauthA
            MvcResult aliceLoginA = mockMvc.perform(post("/v1/api/auth/login").with(bearerHeader(bearerA))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(JSON.writeValueAsString(Map.of("username", aliceName, "password", USER_PASS))))
                    .andReturn();
            assertEquals(200, aliceLoginA.getResponse().getStatus());
            JsonNode aliceJson = JSON.readTree(aliceLoginA.getResponse().getContentAsString());
            assertEquals("AUTHENTICATED", aliceJson.get("status").asText());
            assertTrue(aliceJson.get("authenticated").asBoolean());

            User provisionedAlice = userRepository.findAllByUsernameIgnoreCase(aliceName).stream().findFirst().orElseThrow();
            MvcResult aliceOAuthRes = mockMvc.perform(
                    get("/v1/api/users/" + provisionedAlice.getId() + "/oauth-clients").with(adminUser())).andReturn();
            assertEquals(200, aliceOAuthRes.getResponse().getStatus());
            JsonNode aliceOAuthList = JSON.readTree(aliceOAuthRes.getResponse().getContentAsString());
            assertEquals(1, aliceOAuthList.size(), "JIT user must be assigned ONLY to calling client");
            assertEquals(oauthA.id(), aliceOAuthList.get(0).get("clientId").asLong());
            assertTrue(aliceOAuthList.get(0).get("enabled").asBoolean());

            MvcResult aliceRadRes = mockMvc.perform(
                    get("/v1/api/users/" + provisionedAlice.getId() + "/radius-clients").with(adminUser())).andReturn();
            assertEquals(200, aliceRadRes.getResponse().getStatus());
            JsonNode aliceRadList = JSON.readTree(aliceRadRes.getResponse().getContentAsString());
            assertEquals(0, aliceRadList.size(), "JIT user must not be auto-assigned to RADIUS clients");

            // Unassigned OAuthClient B must deny Alice
            MvcResult aliceLoginB = mockMvc.perform(post("/v1/api/auth/login").with(bearerHeader(bearerB))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(JSON.writeValueAsString(Map.of("username", aliceName, "password", USER_PASS))))
                    .andReturn();
            assertRejected4xx(aliceLoginB.getResponse().getStatus(), "Alice on unassigned OAuthClient B");
            assertJsonFieldNotTrue(aliceLoginB, "authenticated");

            // Unassigned RADIUS client must reject Alice
            byte[] reqAuthAliceRad = randomAuthenticator();
            byte[] radResp = sendRadiusPacket("127.0.0.1",
                    buildAccessRequest(41, reqAuthAliceRad, aliceName, USER_PASS, null, radSec), 2000);
            assertNotNull(radResp);
            assertEquals(3, radResp[0] & 0xFF, "Unassigned NAS " + radId + " must reject JIT LDAP user");
            assertValidResponseAuthenticator(radResp, reqAuthAliceRad, radSec);

            // Branch 2: PASSWORD_AND_OTP calling client (enrollment branch) -> ENROLLMENT_REQUIRED & assigned ONLY to oauthC
            MvcResult bobLoginC = mockMvc.perform(post("/v1/api/auth/login").with(bearerHeader(bearerC))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(JSON.writeValueAsString(Map.of("username", bobName, "password", USER_PASS))))
                    .andReturn();
            assertEquals(200, bobLoginC.getResponse().getStatus());
            JsonNode bobJson = JSON.readTree(bobLoginC.getResponse().getContentAsString());
            assertEquals("ENROLLMENT_REQUIRED", bobJson.get("status").asText());

            User provisionedBob = userRepository.findAllByUsernameIgnoreCase(bobName).stream().findFirst().orElseThrow();
            MvcResult bobOAuthRes = mockMvc.perform(
                    get("/v1/api/users/" + provisionedBob.getId() + "/oauth-clients").with(adminUser())).andReturn();
            assertEquals(200, bobOAuthRes.getResponse().getStatus());
            JsonNode bobOAuthList = JSON.readTree(bobOAuthRes.getResponse().getContentAsString());
            assertEquals(1, bobOAuthList.size(), "MFA JIT user must be assigned ONLY to calling OAuthClient C");
            assertEquals(oauthC.id(), bobOAuthList.get(0).get("clientId").asLong());
            assertTrue(bobOAuthList.get(0).get("enabled").asBoolean());

            MvcResult bobRadRes = mockMvc.perform(
                    get("/v1/api/users/" + provisionedBob.getId() + "/radius-clients").with(adminUser())).andReturn();
            assertEquals(200, bobRadRes.getResponse().getStatus());
            JsonNode bobRadList = JSON.readTree(bobRadRes.getResponse().getContentAsString());
            assertEquals(0, bobRadList.size(), "MFA JIT user must not be auto-assigned to RADIUS clients");

            MvcResult bobLoginA = mockMvc.perform(post("/v1/api/auth/login").with(bearerHeader(bearerA))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(JSON.writeValueAsString(Map.of("username", bobName, "password", USER_PASS))))
                    .andReturn();
            assertRejected4xx(bobLoginA.getResponse().getStatus(), "Bob on unassigned OAuthClient A");
            assertJsonFieldNotTrue(bobLoginA, "authenticated");

            // Disabling an LDAP JIT user's assignment must stay denied and must not auto-reenable on login
            putOAuthAssignment(provisionedAlice.getId(), oauthA.id(), false, null, false);
            MvcResult aliceDisabledLogin = mockMvc.perform(post("/v1/api/auth/login").with(bearerHeader(bearerA))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(JSON.writeValueAsString(Map.of("username", aliceName, "password", USER_PASS))))
                    .andReturn();
            assertRejected4xx(aliceDisabledLogin.getResponse().getStatus(), "Disabled JIT user on assigned OAuthClient A");
            assertJsonFieldNotTrue(aliceDisabledLogin, "authenticated");

            MvcResult aliceBindingRes = mockMvc.perform(
                    get("/v1/api/users/" + provisionedAlice.getId() + "/oauth-clients/" + oauthA.id()).with(adminUser()))
                    .andReturn();
            assertEquals(200, aliceBindingRes.getResponse().getStatus());
            assertFalse(JSON.readTree(aliceBindingRes.getResponse().getContentAsString()).get("enabled").asBoolean(),
                    "LDAP login with autoProvision=true must not re-enable a disabled assignment");

            // With autoProvision=false, unknown LDAP user Charlie is denied and neither user nor assignment is created
            dir.setAutoProvision(false);
            ldapDirectoryRepository.saveAndFlush(dir);
            MvcResult charlieLogin = mockMvc.perform(post("/v1/api/auth/login").with(bearerHeader(bearerA))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(JSON.writeValueAsString(Map.of("username", charlieName, "password", USER_PASS))))
                    .andReturn();
            assertRejected4xx(charlieLogin.getResponse().getStatus(), "LDAP user with autoProvision=false");
            assertJsonFieldNotTrue(charlieLogin, "authenticated");
            assertTrue(userRepository.findAllByUsernameIgnoreCase(charlieName).isEmpty(),
                    "autoProvision=false must not create a local user");
        }
    }

    // -------------------------------------------------------------------------
    // 14. Deleting OAuthClient, RadiusClient, or User cleans up assignments
    // -------------------------------------------------------------------------
    @Test
    void deletingClientOrUserCleansUpAssignmentsWithoutErrors() throws Exception {
        deleteAllRadiusClients();
        CreatedOAuthClient oa1 = createOAuthClient("del-oa-1", null, true, ALL_SCOPES);
        CreatedOAuthClient oa2 = createOAuthClient("del-oa-2", null, true, ALL_SCOPES);
        long rc1 = createRadiusClient("del-rc-1", "127.0.0.1", radiusSecret("del1"), true, null);

        CreatedUser u = createUserWithToken("del-user", null,
                List.of(binding(oa1.id(), true, null), binding(oa2.id(), true, null)),
                List.of(binding(rc1, true, null)));

        assertDeleteOk(mockMvc.perform(delete("/v1/api/oauth-clients/" + oa1.id()).with(adminUser()))
                .andReturn().getResponse().getStatus(), "DELETE oauth-client");

        JsonNode afterOAuthDel = JSON.readTree(mockMvc.perform(
                get("/v1/api/users/" + u.id() + "/oauth-clients").with(adminUser()))
                .andReturn().getResponse().getContentAsString());
        assertEquals(1, afterOAuthDel.size());
        assertEquals(oa2.id(), afterOAuthDel.get(0).get("clientId").asLong());

        assertDeleteOk(mockMvc.perform(delete("/v1/api/radius-clients/" + rc1).with(adminUser()))
                .andReturn().getResponse().getStatus(), "DELETE radius-client");

        JsonNode afterRadDel = JSON.readTree(mockMvc.perform(
                get("/v1/api/users/" + u.id() + "/radius-clients").with(adminUser()))
                .andReturn().getResponse().getContentAsString());
        assertEquals(0, afterRadDel.size());

        assertDeleteOk(mockMvc.perform(delete("/v1/api/users/" + u.id()).with(adminUser()))
                .andReturn().getResponse().getStatus(), "DELETE user");
        assertEquals(404, mockMvc.perform(get("/v1/api/users/" + u.id()).with(adminUser()))
                .andReturn().getResponse().getStatus());
    }

    // -------------------------------------------------------------------------
    // 15. Cross-type client assignments are strictly isolated (OAuth != RADIUS)
    // -------------------------------------------------------------------------
    @Test
    void crossTypeClientAssignmentsAreStrictlyIsolated() throws Exception {
        deleteAllRadiusClients();
        String radSec = radiusSecret("iso-rad");
        CreatedOAuthClient oauthClient = createOAuthClient("iso-oauth", AuthMode.PASSWORD_ONLY, true, ALL_SCOPES);
        long radClientId = createRadiusClient("iso-rad", "127.0.0.1", radSec, true, AuthMode.PASSWORD_ONLY);
        String bearer = fetchBearerToken(oauthClient);

        long step = stableCurrentStep();
        String secOAuthUser = distinctSecret(step);
        String secRadUser = distinctSecret(step);
        CreatedUser oauthOnlyUser = createUserWithToken("oauth-only-user", secOAuthUser,
                List.of(binding(oauthClient.id(), true, null)), List.of());
        CreatedUser radiusOnlyUser = createUserWithToken("radius-only-user", secRadUser,
                List.of(), List.of(binding(radClientId, true, null)));

        // oauthOnlyUser succeeds on OAuth, rejected on RADIUS
        MvcResult oauthOk = mockMvc.perform(post("/v1/api/auth/login").with(bearerHeader(bearer))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of("username", oauthOnlyUser.username(), "password", USER_PASS))))
                .andReturn();
        assertEquals(200, oauthOk.getResponse().getStatus());
        assertTrue(JSON.readTree(oauthOk.getResponse().getContentAsString()).get("authenticated").asBoolean());

        byte[] reqAuthOAuthUserRad = randomAuthenticator();
        byte[] radDenyOAuthUser = sendRadiusPacket("127.0.0.1",
                buildAccessRequest(51, reqAuthOAuthUserRad, oauthOnlyUser.username(), USER_PASS, null, radSec), 2000);
        assertNotNull(radDenyOAuthUser);
        assertEquals(3, radDenyOAuthUser[0] & 0xFF,
                "User assigned only to OAuthClient must be rejected on RADIUS");
        assertValidResponseAuthenticator(radDenyOAuthUser, reqAuthOAuthUserRad, radSec);

        // radiusOnlyUser succeeds on RADIUS, rejected on all 4 OAuth protected APIs
        byte[] reqAuthRadUserOk = randomAuthenticator();
        byte[] radAccept = sendRadiusPacket("127.0.0.1",
                buildAccessRequest(52, reqAuthRadUserOk, radiusOnlyUser.username(), USER_PASS, null, radSec), 2000);
        assertNotNull(radAccept);
        assertEquals(2, radAccept[0] & 0xFF);
        assertValidResponseAuthenticator(radAccept, reqAuthRadUserOk, radSec);

        MvcResult radUserOAuthLogin = mockMvc.perform(post("/v1/api/auth/login").with(bearerHeader(bearer))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of("username", radiusOnlyUser.username(), "password", USER_PASS))))
                .andReturn();
        assertRejected4xx(radUserOAuthLogin.getResponse().getStatus(), "RADIUS-only user on /v1/api/auth/login");
        assertJsonFieldNotTrue(radUserOAuthLogin, "authenticated");

        String totpPrev = otpForStep(secRadUser, step - 1);
        MvcResult radUserOtpVal = mockMvc.perform(post("/v1/api/otp/validate").with(bearerHeader(bearer))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of("username", radiusOnlyUser.username(), "otp", totpPrev))))
                .andReturn();
        assertRejected4xx(radUserOtpVal.getResponse().getStatus(), "RADIUS-only user on /v1/api/otp/validate");
        assertJsonFieldNotTrue(radUserOtpVal, "valid");

        String challenge = "CHAL" + uniqueSuffix().toUpperCase(Locale.ROOT);
        String ocraOtp = ocraService.generateOcra(secRadUser, challenge);
        MvcResult radUserOcraVal = mockMvc.perform(post("/v1/api/otp/validate-ocra").with(bearerHeader(bearer))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of(
                                "username", radiusOnlyUser.username(), "challenge", challenge, "otp", ocraOtp))))
                .andReturn();
        assertRejected4xx(radUserOcraVal.getResponse().getStatus(), "RADIUS-only user on /v1/api/otp/validate-ocra");
        assertJsonFieldNotTrue(radUserOcraVal, "valid");

        String totpNext = otpForStep(secRadUser, step + 1);
        MvcResult radUserPreauth = mockMvc.perform(post("/v1/api/mfa/preauth").with(bearerHeader(bearer))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of(
                                "username", radiusOnlyUser.username(), "otp", Integer.parseInt(totpNext)))))
                .andReturn();
        int preStatus = radUserPreauth.getResponse().getStatus();
        String preBody = radUserPreauth.getResponse().getContentAsString().trim();
        assertTrue((preStatus >= 400 && preStatus < 500 && preStatus != 404 && preStatus != 405)
                        || (preStatus == 200 && "false".equalsIgnoreCase(preBody)),
                "RADIUS-only user on /v1/api/mfa/preauth must be denied, got " + preStatus + " body=" + preBody);
        assertTrue(approvalRepository.findByUserId(radiusOnlyUser.id()).isEmpty(),
                "Denied /v1/api/mfa/preauth for RADIUS-only user must not create MfaApproval");
    }

    // -------------------------------------------------------------------------
    // 16. Username case-insensitivity & realm stripping enforce assignments
    // -------------------------------------------------------------------------
    @Test
    void usernameCaseInsensitivityAndRealmStrippingEnforceClientAssignments() throws Exception {
        deleteAllRadiusClients();
        CreatedOAuthClient oa = createOAuthClient("case-oa", AuthMode.PASSWORD_ONLY, true, ALL_SCOPES);
        CreatedOAuthClient ob = createOAuthClient("case-ob", AuthMode.PASSWORD_ONLY, true, ALL_SCOPES);
        String bearerA = fetchBearerToken(oa);
        String bearerB = fetchBearerToken(ob);

        String radSec1 = radiusSecret("case-nas1");
        String radSec2 = radiusSecret("case-nas2");
        long nas1 = createRadiusClient("case-nas-1", "127.0.0.1", radSec1, true, AuthMode.PASSWORD_ONLY);
        createRadiusClient("case-nas-2", "127.0.0.2", radSec2, true, AuthMode.PASSWORD_ONLY);

        CreatedUser u = createUserWithToken("case-user", null,
                List.of(binding(oa.id(), true, null)),
                List.of(binding(nas1, true, null)));

        String upperRealmUser = u.username().toUpperCase(Locale.ROOT) + "@corp.example";

        // OAuth assigned A succeeds, unassigned B denied
        MvcResult oauthOk = mockMvc.perform(post("/v1/api/auth/login").with(bearerHeader(bearerA))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of("username", upperRealmUser, "password", USER_PASS))))
                .andReturn();
        assertEquals(200, oauthOk.getResponse().getStatus());
        assertTrue(JSON.readTree(oauthOk.getResponse().getContentAsString()).get("authenticated").asBoolean());

        MvcResult oauthDeny = mockMvc.perform(post("/v1/api/auth/login").with(bearerHeader(bearerB))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of("username", upperRealmUser, "password", USER_PASS))))
                .andReturn();
        assertRejected4xx(oauthDeny.getResponse().getStatus(), "Unassigned OAuth login with realm-qualified uppercase username");
        assertJsonFieldNotTrue(oauthDeny, "authenticated");

        // RADIUS assigned NAS-1 accepts, unassigned NAS-2 rejects
        byte[] reqAuthNas1 = randomAuthenticator();
        byte[] radOk = sendRadiusPacket("127.0.0.1",
                buildAccessRequest(61, reqAuthNas1, upperRealmUser, USER_PASS, null, radSec1), 2000);
        assertNotNull(radOk);
        assertEquals(2, radOk[0] & 0xFF, "Assigned NAS-1 must accept realm-qualified uppercase username");
        assertValidResponseAuthenticator(radOk, reqAuthNas1, radSec1);

        byte[] reqAuthNas2 = randomAuthenticator();
        byte[] radDeny = sendRadiusPacket("127.0.0.2",
                buildAccessRequest(62, reqAuthNas2, upperRealmUser, USER_PASS, null, radSec2), 2000);
        assertNotNull(radDeny);
        assertEquals(3, radDeny[0] & 0xFF, "Unassigned NAS-2 must reject realm-qualified uppercase username");
        assertValidResponseAuthenticator(radDeny, reqAuthNas2, radSec2);
    }

    // -------------------------------------------------------------------------
    // 17. Assigned unenrolled local user enrolls into OtpToken without User.secret
    // -------------------------------------------------------------------------
    @Test
    void assignedUnenrolledLocalUserEnrollsIntoOtpTokenWithoutLegacyUserSecret() throws Exception {
        CreatedOAuthClient oa = createOAuthClient("local-enroll", AuthMode.PASSWORD_AND_OTP, true, ALL_SCOPES);
        String bearer = fetchBearerToken(oa);

        CreatedUser u = createUserWithToken("local-enroll-user", null,
                List.of(binding(oa.id(), true, null)), List.of());

        MvcResult enrollRes = mockMvc.perform(post("/v1/api/auth/login").with(bearerHeader(bearer))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of("username", u.username(), "password", USER_PASS))))
                .andReturn();
        assertEquals(200, enrollRes.getResponse().getStatus());
        JsonNode enrollJson = JSON.readTree(enrollRes.getResponse().getContentAsString());
        assertEquals("ENROLLMENT_REQUIRED", enrollJson.get("status").asText());
        assertFalse(enrollJson.get("authenticated").asBoolean());
        String enrolledSecret = enrollJson.path("secret").asText("");
        assertFalse(enrolledSecret.isBlank(), "Enrollment response must include TOTP secret");

        User reloaded = userRepository.findById(u.id()).orElseThrow();
        assertNotNull(reloaded.getOtpToken(), "Local enrollment must persist an OtpToken on the user");
        assertEquals(enrolledSecret, reloaded.getOtpToken().getSecret());

        long step = stableCurrentStep();
        String otp = otpForStep(enrolledSecret, step);
        MvcResult loginOk = mockMvc.perform(post("/v1/api/auth/login").with(bearerHeader(bearer))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of(
                                "username", u.username(), "password", USER_PASS, "otp", otp))))
                .andReturn();
        assertEquals(200, loginOk.getResponse().getStatus());
        JsonNode loginJson = JSON.readTree(loginOk.getResponse().getContentAsString());
        assertEquals("AUTHENTICATED", loginJson.get("status").asText());
        assertTrue(loginJson.get("authenticated").asBoolean());
    }

    // -------------------------------------------------------------------------
    // 18. Empty-type unified client listing & disabled User still blocked
    // -------------------------------------------------------------------------
    @Test
    void emptyTypeUnifiedListingReturnsEmptyArrayAndDisabledUserStillBlocked() throws Exception {
        deleteAllOAuthClients();
        deleteAllRadiusClients();

        // Part A: only OAuth clients -> ?type=RADIUS is [], ?type=OAUTH2 lists OAuth client
        CreatedOAuthClient oa = createOAuthClient("only-oa", AuthMode.PASSWORD_ONLY, true, ALL_SCOPES);
        MvcResult emptyRadius = mockMvc.perform(get("/v1/api/clients/all").param("type", "RADIUS").with(adminUser()))
                .andReturn();
        assertEquals(200, emptyRadius.getResponse().getStatus());
        JsonNode emptyRadiusArr = JSON.readTree(emptyRadius.getResponse().getContentAsString());
        assertTrue(emptyRadiusArr.isArray() && emptyRadiusArr.isEmpty(),
                "Expected [] for ?type=RADIUS when no RADIUS clients exist");

        MvcResult hasOAuth = mockMvc.perform(get("/v1/api/clients/all").param("type", "OAUTH2").with(adminUser()))
                .andReturn();
        assertEquals(200, hasOAuth.getResponse().getStatus());
        assertNotNull(findCatalogEntry(JSON.readTree(hasOAuth.getResponse().getContentAsString()), "OAUTH2", oa.id()));

        // Only RADIUS clients -> ?type=OAUTH2 is [], ?type=RADIUS lists RADIUS client
        assertDeleteOk(mockMvc.perform(delete("/v1/api/oauth-clients/" + oa.id()).with(adminUser()))
                .andReturn().getResponse().getStatus(), "DELETE only-oa");
        String radSec = radiusSecret("only-rc");
        long rc = createRadiusClient("only-rc", "127.0.0.1", radSec, true, AuthMode.PASSWORD_ONLY);

        MvcResult emptyOAuth = mockMvc.perform(get("/v1/api/clients/all").param("type", "OAUTH2").with(adminUser()))
                .andReturn();
        assertEquals(200, emptyOAuth.getResponse().getStatus());
        JsonNode emptyOAuthArr = JSON.readTree(emptyOAuth.getResponse().getContentAsString());
        assertTrue(emptyOAuthArr.isArray() && emptyOAuthArr.isEmpty(),
                "Expected [] for ?type=OAUTH2 when no OAuth clients exist");

        MvcResult hasRadius = mockMvc.perform(get("/v1/api/clients/all").param("type", "RADIUS").with(adminUser()))
                .andReturn();
        assertEquals(200, hasRadius.getResponse().getStatus());
        assertNotNull(findCatalogEntry(JSON.readTree(hasRadius.getResponse().getContentAsString()), "RADIUS", rc));

        // Part B: disabled User is still denied on OAuth & RADIUS even when assignments have enabled=true
        CreatedOAuthClient oa2 = createOAuthClient("user-disable-oa", AuthMode.PASSWORD_ONLY, true, ALL_SCOPES);
        String bearer = fetchBearerToken(oa2);
        CreatedUser u = createUserWithToken("disabled-flag-user", null,
                List.of(binding(oa2.id(), true, null)),
                List.of(binding(rc, true, null)));

        MvcResult beforeDisableOAuth = mockMvc.perform(post("/v1/api/auth/login").with(bearerHeader(bearer))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of("username", u.username(), "password", USER_PASS))))
                .andReturn();
        assertEquals(200, beforeDisableOAuth.getResponse().getStatus());
        assertTrue(JSON.readTree(beforeDisableOAuth.getResponse().getContentAsString()).get("authenticated").asBoolean());

        byte[] reqAuthBefore = randomAuthenticator();
        byte[] beforeDisableRad = sendRadiusPacket("127.0.0.1",
                buildAccessRequest(71, reqAuthBefore, u.username(), USER_PASS, null, radSec), 2000);
        assertNotNull(beforeDisableRad);
        assertEquals(2, beforeDisableRad[0] & 0xFF);
        assertValidResponseAuthenticator(beforeDisableRad, reqAuthBefore, radSec);

        // Disable user account itself while keeping enabled=true on client assignments
        MvcResult disableUser = mockMvc.perform(put("/v1/api/users/" + u.id()).with(adminUser())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of("username", u.username(), "enabled", false))))
                .andReturn();
        assertEquals(200, disableUser.getResponse().getStatus());

        MvcResult afterDisableOAuth = mockMvc.perform(post("/v1/api/auth/login").with(bearerHeader(bearer))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of("username", u.username(), "password", USER_PASS))))
                .andReturn();
        assertRejected4xx(afterDisableOAuth.getResponse().getStatus(), "Disabled user on OAuth login");
        assertJsonFieldNotTrue(afterDisableOAuth, "authenticated");

        byte[] reqAuthAfter = randomAuthenticator();
        byte[] afterDisableRad = sendRadiusPacket("127.0.0.1",
                buildAccessRequest(72, reqAuthAfter, u.username(), USER_PASS, null, radSec), 2000);
        assertNotNull(afterDisableRad);
        assertEquals(3, afterDisableRad[0] & 0xFF, "Disabled user must be rejected on RADIUS even if binding enabled=true");
        assertValidResponseAuthenticator(afterDisableRad, reqAuthAfter, radSec);
    }

    // =========================================================================
    // JSON, TOTP & RADIUS Wire Helpers
    // =========================================================================

    private static JsonNode findCatalogEntry(JsonNode arr, String type, long id) {
        if (arr == null || !arr.isArray()) {
            return null;
        }
        for (JsonNode n : arr) {
            if (n.hasNonNull("type") && n.hasNonNull("id")
                    && type.equals(n.get("type").asText())
                    && id == n.get("id").asLong()) {
                return n;
            }
        }
        return null;
    }

    private static JsonNode findById(JsonNode arr, long id) {
        if (arr == null || !arr.isArray()) {
            return null;
        }
        for (JsonNode n : arr) {
            if (n.hasNonNull("id") && id == n.get("id").asLong()) {
                return n;
            }
        }
        return null;
    }

    private static void assertNoClientSecretsExposed(JsonNode entry) {
        for (String forbidden : List.of("clientSecret", "clientSecretHash", "sharedSecret", "secret")) {
            assertTrue(entry.path(forbidden).isMissingNode() || entry.path(forbidden).isNull(),
                    "Unified listing entry must not expose " + forbidden);
        }
    }

    private static void assertNoSecretMaterialInBody(String body, String... knownSecrets) {
        if (body == null) {
            return;
        }
        assertFalse(body.contains("$2a$") || body.contains("$2b$") || body.contains("$2y$"),
                "Response must never leak BCrypt secret hash");
        for (String s : knownSecrets) {
            if (s != null && !s.isBlank()) {
                assertFalse(body.contains(s), "Response must never expose client secret material");
            }
        }
    }

    private long stableCurrentStep() throws InterruptedException {
        while (true) {
            long nowMs = clock.millis();
            long offsetInBucket = nowMs % 30000L;
            if (offsetInBucket <= 23000L) {
                return nowMs / 30000L;
            }
            Thread.sleep(250);
        }
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
        return "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
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

    private byte[] randomAuthenticator() {
        byte[] auth = new byte[16];
        secureRandom.nextBytes(auth);
        return auth;
    }

    private byte[] buildAccessRequest(int identifier, byte[] requestAuthenticator, String username,
                                      String passwordOrOtp, byte[] state, String sharedSecret) throws Exception {
        ByteArrayOutputStream attrs = new ByteArrayOutputStream();
        // RFC 3579 Message-Authenticator (Attribute 80, length 18) with 16 zero bytes first
        attrs.write(80);
        attrs.write(18);
        attrs.write(new byte[16]);

        byte[] userBytes = username.getBytes(StandardCharsets.UTF_8);
        attrs.write(1);
        attrs.write(2 + userBytes.length);
        attrs.write(userBytes);

        if (passwordOrOtp != null) {
            byte[] encrypted = obfuscatePassword(passwordOrOtp, requestAuthenticator, sharedSecret);
            attrs.write(2);
            attrs.write(2 + encrypted.length);
            attrs.write(encrypted);
        }
        if (state != null) {
            attrs.write(24);
            attrs.write(2 + state.length);
            attrs.write(state);
        }

        byte[] attrBytes = attrs.toByteArray();
        int totalLength = 20 + attrBytes.length;
        ByteBuffer buf = ByteBuffer.allocate(totalLength);
        buf.put((byte) 1);
        buf.put((byte) (identifier & 0xFF));
        buf.putShort((short) totalLength);
        buf.put(requestAuthenticator);
        buf.put(attrBytes);
        byte[] packet = buf.array();

        Mac mac = Mac.getInstance("HmacMD5");
        mac.init(new SecretKeySpec(sharedSecret.getBytes(StandardCharsets.UTF_8), "HmacMD5"));
        byte[] hmac = mac.doFinal(packet);
        System.arraycopy(hmac, 0, packet, 22, 16);
        return packet;
    }

    private static byte[] obfuscatePassword(String password, byte[] requestAuthenticator, String sharedSecret)
            throws Exception {
        byte[] pwBytes = password.getBytes(StandardCharsets.UTF_8);
        int len = Math.max(16, ((pwBytes.length + 15) / 16) * 16);
        byte[] padded = new byte[len];
        System.arraycopy(pwBytes, 0, padded, 0, pwBytes.length);

        byte[] secretBytes = sharedSecret.getBytes(StandardCharsets.UTF_8);
        byte[] cipher = new byte[len];
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        byte[] prev = requestAuthenticator;
        for (int i = 0; i < len; i += 16) {
            md5.reset();
            md5.update(secretBytes);
            md5.update(prev);
            byte[] digest = md5.digest();
            for (int j = 0; j < 16; j++) {
                cipher[i + j] = (byte) (padded[i + j] ^ digest[j]);
            }
            prev = Arrays.copyOfRange(cipher, i, i + 16);
        }
        return cipher;
    }

    private byte[] sendRadiusPacket(String bindIp, byte[] packetBytes, int timeoutMs) throws Exception {
        try (DatagramSocket socket = new DatagramSocket(new InetSocketAddress(InetAddress.getByName(bindIp), 0))) {
            socket.setSoTimeout(timeoutMs);
            DatagramPacket req = new DatagramPacket(
                    packetBytes, packetBytes.length, InetAddress.getByName("127.0.0.1"), radiusServer.getLocalPort());
            socket.send(req);
            byte[] buf = new byte[4096];
            DatagramPacket resp = new DatagramPacket(buf, buf.length);
            try {
                socket.receive(resp);
                return Arrays.copyOf(resp.getData(), resp.getLength());
            } catch (SocketTimeoutException e) {
                return null;
            }
        }
    }

    private static byte[] extractAttribute(byte[] responsePacket, int targetType) {
        int pos = 20;
        while (pos + 2 <= responsePacket.length) {
            int type = responsePacket[pos] & 0xFF;
            int len = responsePacket[pos + 1] & 0xFF;
            if (len < 2 || pos + len > responsePacket.length) {
                break;
            }
            if (type == targetType) {
                return Arrays.copyOfRange(responsePacket, pos + 2, pos + len);
            }
            pos += len;
        }
        return null;
    }

    private static void assertValidResponseAuthenticator(byte[] responsePacket, byte[] requestAuthenticator,
                                                         String sharedSecret) throws Exception {
        assertTrue(responsePacket.length >= 20);
        int declaredLen = ((responsePacket[2] & 0xFF) << 8) | (responsePacket[3] & 0xFF);
        assertEquals(responsePacket.length, declaredLen);

        byte[] actual = Arrays.copyOfRange(responsePacket, 4, 20);
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        md5.update(responsePacket, 0, 4);
        md5.update(requestAuthenticator);
        if (responsePacket.length > 20) {
            md5.update(responsePacket, 20, responsePacket.length - 20);
        }
        md5.update(sharedSecret.getBytes(StandardCharsets.UTF_8));
        assertArrayEquals(md5.digest(), actual, "Invalid RADIUS Response Authenticator");
    }

    // Minimal BER/LDAP mock server for LDAP JIT tests
    private static final class TestLdapServer implements Closeable {
        private final ServerSocket serverSocket;
        private final Map<String, String> users;
        private volatile boolean running = true;

        TestLdapServer(Map<String, String> users) throws IOException {
            this.users = new HashMap<>(users);
            this.serverSocket = new ServerSocket(0, 16, InetAddress.getByName("127.0.0.1"));
            Thread acceptThread = new Thread(this::acceptLoop, "grader-ldap-accept");
            acceptThread.setDaemon(true);
            acceptThread.start();
        }

        int getPort() {
            return serverSocket.getLocalPort();
        }

        private void acceptLoop() {
            while (running) {
                try {
                    Socket socket = serverSocket.accept();
                    Thread worker = new Thread(() -> handleClient(socket), "grader-ldap-client");
                    worker.setDaemon(true);
                    worker.start();
                } catch (IOException e) {
                    if (running) {
                        break;
                    }
                }
            }
        }

        private void handleClient(Socket socket) {
            try (InputStream in = socket.getInputStream(); OutputStream out = socket.getOutputStream()) {
                while (running) {
                    int tag = in.read();
                    if (tag == -1) {
                        break;
                    }
                    int len = readLength(in);
                    byte[] payload = readBytes(in, len);
                    ByteBufferStream bin = new ByteBufferStream(payload);
                    if (bin.read() != 0x02) {
                        break;
                    }
                    int idLen = readLength(bin);
                    byte[] idBytes = readBytes(bin, idLen);
                    int messageId = 0;
                    for (byte b : idBytes) {
                        messageId = (messageId << 8) | (b & 0xFF);
                    }
                    int opTag = bin.read();
                    int opLen = readLength(bin);
                    byte[] opBytes = readBytes(bin, opLen);
                    ByteBufferStream opIn = new ByteBufferStream(opBytes);

                    if (opTag == 0x60) {
                        opIn.read();
                        readBytes(opIn, readLength(opIn));
                        opIn.read();
                        String bindDn = new String(readBytes(opIn, readLength(opIn)), StandardCharsets.UTF_8);
                        opIn.read();
                        String pass = new String(readBytes(opIn, readLength(opIn)), StandardCharsets.UTF_8);

                        boolean ok = "cn=admin,dc=example,dc=org".equals(bindDn) && LDAP_BIND_PASSWORD.equals(pass);
                        if (!ok) {
                            for (Map.Entry<String, String> entry : users.entrySet()) {
                                String expectedDn = "uid=" + entry.getKey() + ",ou=users,dc=example,dc=org";
                                if (expectedDn.equals(bindDn) && entry.getValue().equals(pass)) {
                                    ok = true;
                                    break;
                                }
                            }
                        }
                        sendResult(out, messageId, 0x61, ok ? 0 : 49);
                    } else if (opTag == 0x63) {
                        opIn.read();
                        readBytes(opIn, readLength(opIn));
                        for (int i = 0; i < 5; i++) {
                            opIn.read();
                            readBytes(opIn, readLength(opIn));
                        }
                        String remaining = new String(opIn.readRemaining(), StandardCharsets.UTF_8);
                        for (String u : users.keySet()) {
                            String marker = String.valueOf((char) 0x04) + String.valueOf((char) u.length()) + u;
                            if (remaining.contains(marker)) {
                                sendSearchResultEntry(out, messageId, "uid=" + u + ",ou=users,dc=example,dc=org", u);
                                break;
                            }
                        }
                        sendResult(out, messageId, 0x65, 0);
                    } else if (opTag == 0x42) {
                        break;
                    }
                }
            } catch (Exception ignored) {
            } finally {
                try {
                    socket.close();
                } catch (IOException ignored) {
                }
            }
        }

        private static final class ByteBufferStream extends InputStream {
            private final byte[] buf;
            private int pos;

            ByteBufferStream(byte[] buf) {
                this.buf = buf;
            }

            @Override
            public int read() {
                return pos < buf.length ? (buf[pos++] & 0xFF) : -1;
            }

            byte[] readRemaining() {
                byte[] rem = Arrays.copyOfRange(buf, pos, buf.length);
                pos = buf.length;
                return rem;
            }
        }

        private static int readLength(InputStream in) throws IOException {
            int b = in.read();
            if (b == -1) {
                throw new EOFException();
            }
            if ((b & 0x80) == 0) {
                return b;
            }
            int num = b & 0x7F;
            int len = 0;
            for (int i = 0; i < num; i++) {
                int next = in.read();
                if (next == -1) {
                    throw new EOFException();
                }
                len = (len << 8) | next;
            }
            return len;
        }

        private static byte[] readBytes(InputStream in, int len) throws IOException {
            byte[] buf = new byte[len];
            int read = 0;
            while (read < len) {
                int n = in.read(buf, read, len - read);
                if (n == -1) {
                    throw new EOFException();
                }
                read += n;
            }
            return buf;
        }

        private static void writeLength(ByteArrayOutputStream out, int len) {
            if (len < 128) {
                out.write(len);
            } else if (len < 256) {
                out.write(0x81);
                out.write(len);
            } else {
                out.write(0x82);
                out.write((len >> 8) & 0xFF);
                out.write(len & 0xFF);
            }
        }

        private static void sendResult(OutputStream out, int messageId, int opTag, int code) throws IOException {
            ByteArrayOutputStream op = new ByteArrayOutputStream();
            op.write(0x0A);
            op.write(1);
            op.write(code);
            op.write(0x04);
            op.write(0);
            op.write(0x04);
            op.write(0);
            writeFrame(out, messageId, opTag, op.toByteArray());
        }

        private static void sendSearchResultEntry(OutputStream out, int messageId, String dn, String uid)
                throws IOException {
            ByteArrayOutputStream entry = new ByteArrayOutputStream();
            byte[] dnBytes = dn.getBytes(StandardCharsets.UTF_8);
            entry.write(0x04);
            writeLength(entry, dnBytes.length);
            entry.write(dnBytes);

            ByteArrayOutputStream attr = new ByteArrayOutputStream();
            byte[] t = "uid".getBytes(StandardCharsets.UTF_8);
            attr.write(0x04);
            writeLength(attr, t.length);
            attr.write(t);
            ByteArrayOutputStream vals = new ByteArrayOutputStream();
            byte[] v = uid.getBytes(StandardCharsets.UTF_8);
            vals.write(0x04);
            writeLength(vals, v.length);
            vals.write(v);
            attr.write(0x31);
            writeLength(attr, vals.size());
            attr.write(vals.toByteArray());

            ByteArrayOutputStream attrs = new ByteArrayOutputStream();
            attrs.write(0x30);
            writeLength(attrs, attr.size());
            attrs.write(attr.toByteArray());

            entry.write(0x30);
            writeLength(entry, attrs.size());
            entry.write(attrs.toByteArray());
            writeFrame(out, messageId, 0x64, entry.toByteArray());
        }

        private static void writeFrame(OutputStream out, int messageId, int opTag, byte[] opBytes) throws IOException {
            ByteArrayOutputStream resp = new ByteArrayOutputStream();
            resp.write(0x02);
            resp.write(1);
            resp.write(messageId);
            resp.write(opTag);
            writeLength(resp, opBytes.length);
            resp.write(opBytes);

            ByteArrayOutputStream frame = new ByteArrayOutputStream();
            frame.write(0x30);
            writeLength(frame, resp.size());
            frame.write(resp.toByteArray());
            out.write(frame.toByteArray());
            out.flush();
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
