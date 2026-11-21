package com.authprovider;

import com.authprovider.config.DatabaseConfigurationBootstrap;
import com.authprovider.entity.AuthMode;
import com.authprovider.entity.LdapDirectory;
import com.authprovider.entity.SecurityPolicy;
import com.authprovider.entity.User;
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
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.servlet.http.Cookie;
import org.apache.commons.codec.binary.Base32;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;

@SpringBootTest(properties = {
        "radius.port=0",
        "radius.bind-address=127.0.0.1",
        "iam.bootstrap.radius.shared-secret=oauth-grader-radius",
        "iam.bootstrap.admin.username=grader-boot-admin",
        "iam.bootstrap.admin.password=GraderBootAdm!123",
        "iam.bootstrap.policy.max-failures=3",
        "iam.bootstrap.policy.lockout-seconds=120",
        "iam.bootstrap.policy.mfa-approval-ttl-seconds=60",
        "iam.bootstrap.policy.challenge-ttl-seconds=60"
})
@AutoConfigureMockMvc
class OAuth2ClientSecurityGraderTest {

    private static final String USER_PASS = "Str0ng!UserPass9";
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Base32 BASE32 = new Base32();

    private static final String SCOPE_AUTH_LOGIN = "auth:login";
    private static final String SCOPE_OTP_VALIDATE = "otp:validate";
    private static final String SCOPE_MFA_PREAUTH = "mfa:preauth";
    private static final List<String> ALL_SCOPES = List.of(
            SCOPE_AUTH_LOGIN, SCOPE_OTP_VALIDATE, SCOPE_MFA_PREAUTH);

    @Autowired private MockMvc mockMvc;
    @Autowired private DatabaseConfigurationBootstrap bootstrap;
    @Autowired private UserService userService;
    @Autowired private UserRepository userRepository;
    @Autowired private AuthFailureRecordRepository failureRepository;
    @Autowired private MfaApprovalRepository approvalRepository;
    @Autowired private RadiusChallengeSessionRepository challengeRepository;
    @Autowired private OtpReplayStateRepository replayRepository;
    @Autowired private OcraChallengeUseRepository ocraRepository;
    @Autowired private SecurityPolicyRepository policyRepository;
    @Autowired private LdapDirectoryRepository ldapDirectoryRepository;
    @Autowired private JdbcTemplate jdbcTemplate;
    @Autowired private TotpService totpService;
    @Autowired private OcraService ocraService;
    @Autowired private SecretGenerator secretGenerator;
    @Autowired private Clock clock;

    @BeforeEach
    void setUp() throws Exception {
        cleanState();
        bootstrap.seed();
        configurePolicy(3, 120, 300, AuthMode.PASSWORD_AND_OTP);
    }

    @AfterEach
    void tearDown() throws Exception {
        cleanState();
        bootstrap.seed();
        configurePolicy(3, 120, 300, AuthMode.PASSWORD_AND_OTP);
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
        deleteAllClients(mockMvc);
        challengeRepository.deleteAll();
        approvalRepository.deleteAll();
        failureRepository.deleteAll();
        replayRepository.deleteAll();
        ocraRepository.deleteAll();
        resetDirectories();
        userRepository.deleteAll();
    }

    private void deleteAllClients(MockMvc mvc) throws Exception {
        MvcResult listRes = getClientsRaw(mvc);
        if (listRes.getResponse().getStatus() != 200) {
            return;
        }
        JsonNode arr = JSON.readTree(listRes.getResponse().getContentAsString());
        if (arr != null && arr.isArray()) {
            for (JsonNode c : arr) {
                if (c.hasNonNull("id")) {
                    mvc.perform(delete("/v1/api/clients/" + c.get("id").asLong()).with(adminUser()));
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

    private void configurePolicy(int maxFailures, long lockoutSeconds, long failureWindowSeconds,
                                 AuthMode defaultAuthMode) {
        configurePolicy(policyRepository, maxFailures, lockoutSeconds, failureWindowSeconds, defaultAuthMode);
    }

    private static void configurePolicy(SecurityPolicyRepository repo, int maxFailures, long lockoutSeconds,
                                        long failureWindowSeconds, AuthMode defaultAuthMode) {
        SecurityPolicy policy = repo.findByName(SecurityPolicy.DEFAULT_NAME).orElseThrow();
        policy.setMaxFailures(maxFailures);
        policy.setMfaMaxFailedAttempts(maxFailures);
        policy.setLockoutSeconds(lockoutSeconds);
        policy.setFailureWindowSeconds(failureWindowSeconds);
        policy.setMfaLockoutWindowSeconds(failureWindowSeconds);
        policy.setDefaultAuthMode(defaultAuthMode);
        repo.saveAndFlush(policy);
    }

    private static RequestPostProcessor adminUser() {
        return SecurityMockMvcRequestPostProcessors.user("grader-boot-admin").roles("ADMIN");
    }

    private User createUser(String username, String password, String secret, AuthMode authMode) {
        return userService.saveUser(User.builder()
                .username(username)
                .password(password)
                .secret(secret)
                .authMode(authMode)
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

    private static String basicAuth(String clientId, String clientSecret) {
        String raw = clientId + ":" + clientSecret;
        return "Basic " + Base64.getEncoder().encodeToString(raw.getBytes(StandardCharsets.UTF_8));
    }

    private static String clientSecret(String tag) {
        String clean = tag.replaceAll("[^A-Za-z0-9_-]", "_");
        String base = "M2mClientSec_" + clean + "_9876543210_ZxQvBnM9-Aa.7";
        return base.length() <= 64 ? base : base.substring(0, 64);
    }

    private static ObjectNode clientPayload(Long id, String clientId, String clientSecret, String name,
                                            boolean enabled, boolean blocked, AuthMode authMode,
                                            List<String> scopes) {
        ObjectNode node = JSON.createObjectNode();
        if (id != null) {
            node.put("id", id);
        }
        if (clientId != null) {
            node.put("clientId", clientId);
        }
        if (clientSecret != null) {
            node.put("clientSecret", clientSecret);
        }
        if (name != null) {
            node.put("name", name);
        }
        node.put("enabled", enabled);
        node.put("blocked", blocked);
        if (authMode != null) {
            node.put("authMode", authMode.name());
        }
        if (scopes != null) {
            ArrayNode arr = node.putArray("scopes");
            for (String s : scopes) {
                arr.add(s);
            }
        }
        return node;
    }

    private MvcResult createClientRaw(MockMvc mvc, ObjectNode payload) throws Exception {
        String json = JSON.writeValueAsString(payload);
        MvcResult res = mvc.perform(post("/v1/api/clients/create")
                        .with(adminUser())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andReturn();
        int status = res.getResponse().getStatus();
        if (status == 404 || status == 405) {
            res = mvc.perform(post("/v1/api/clients")
                            .with(adminUser())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(json))
                    .andReturn();
        }
        return res;
    }

    private JsonNode createClient(MockMvc mvc, String clientId, String secret, String name,
                                  boolean enabled, boolean blocked, AuthMode authMode,
                                  List<String> scopes) throws Exception {
        MvcResult res = createClientRaw(mvc, clientPayload(
                null, clientId, secret, name, enabled, blocked, authMode, scopes));
        int status = res.getResponse().getStatus();
        assertTrue(status >= 200 && status < 300,
                "Expected 2xx creating client " + clientId + ", got " + status
                        + " body=" + res.getResponse().getContentAsString());
        return JSON.readTree(res.getResponse().getContentAsString());
    }

    private JsonNode createClient(String clientId, String secret, List<String> scopes) throws Exception {
        return createClient(mockMvc, clientId, secret, "Client " + clientId, true, false, null, scopes);
    }

    private MvcResult getClientsRaw(MockMvc mvc) throws Exception {
        MvcResult res = mvc.perform(get("/v1/api/clients/all").with(adminUser())).andReturn();
        int status = res.getResponse().getStatus();
        if (status == 404 || status == 405) {
            res = mvc.perform(get("/v1/api/clients").with(adminUser())).andReturn();
        }
        return res;
    }

    private MvcResult getClientRaw(MockMvc mvc, long id) throws Exception {
        return mvc.perform(get("/v1/api/clients/" + id).with(adminUser())).andReturn();
    }

    private MvcResult updateClientRaw(MockMvc mvc, long id, ObjectNode payload) throws Exception {
        return mvc.perform(put("/v1/api/clients/" + id)
                        .with(adminUser())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(payload)))
                .andReturn();
    }

    private JsonNode updateClient(MockMvc mvc, long id, String clientId, String secretOrNull, String name,
                                  boolean enabled, boolean blocked, AuthMode authMode,
                                  List<String> scopes) throws Exception {
        MvcResult res = updateClientRaw(mvc, id, clientPayload(
                null, clientId, secretOrNull, name, enabled, blocked, authMode, scopes));
        int status = res.getResponse().getStatus();
        assertTrue(status >= 200 && status < 300,
                "Expected 2xx updating client " + id + ", got " + status
                        + " body=" + res.getResponse().getContentAsString());
        String body = res.getResponse().getContentAsString();
        if (body == null || body.isBlank()) {
            MvcResult fetched = getClientRaw(mvc, id);
            assertEquals(200, fetched.getResponse().getStatus(),
                    "Expected 200 fetching updated client " + id + ", got " + fetched.getResponse().getStatus());
            body = fetched.getResponse().getContentAsString();
        }
        return JSON.readTree(body);
    }

    private MvcResult deleteClientRaw(MockMvc mvc, long id) throws Exception {
        return mvc.perform(delete("/v1/api/clients/" + id).with(adminUser())).andReturn();
    }

    private MvcResult requestTokenRaw(MockMvc mvc, String basicHeader, String grantType, String scope) throws Exception {
        var req = post("/oauth2/token").contentType(MediaType.APPLICATION_FORM_URLENCODED);
        if (basicHeader != null) {
            req.header(HttpHeaders.AUTHORIZATION, basicHeader);
        }
        if (grantType != null) {
            req.param("grant_type", grantType);
        }
        if (scope != null) {
            req.param("scope", scope);
        }
        return mvc.perform(req).andReturn();
    }

    private String issueToken(MockMvc mvc, String clientId, String secret, String scope) throws Exception {
        MvcResult res = requestTokenRaw(mvc, basicAuth(clientId, secret), "client_credentials", scope);
        assertEquals(200, res.getResponse().getStatus(),
                "Expected 200 from /oauth2/token for " + clientId + ", got " + res.getResponse().getStatus()
                        + " body=" + res.getResponse().getContentAsString());
        JsonNode body = JSON.readTree(res.getResponse().getContentAsString());
        String token = body.path("access_token").asText("");
        assertFalse(token.isBlank(), "access_token must not be blank");
        return token;
    }

    private String issueToken(String clientId, String secret, String scope) throws Exception {
        return issueToken(mockMvc, clientId, secret, scope);
    }

    private MvcResult introspectRaw(MockMvc mvc, String basicHeader, String token) throws Exception {
        var req = post("/oauth2/introspect").contentType(MediaType.APPLICATION_FORM_URLENCODED);
        if (basicHeader != null) {
            req.header(HttpHeaders.AUTHORIZATION, basicHeader);
        }
        if (token != null) {
            req.param("token", token);
        }
        return mvc.perform(req).andReturn();
    }

    private JsonNode introspect(MockMvc mvc, String clientId, String secret, String token) throws Exception {
        MvcResult res = introspectRaw(mvc, basicAuth(clientId, secret), token);
        assertEquals(200, res.getResponse().getStatus(),
                "Expected 200 from /oauth2/introspect, got " + res.getResponse().getStatus()
                        + " body=" + res.getResponse().getContentAsString());
        return JSON.readTree(res.getResponse().getContentAsString());
    }

    private static void assertRejected4xx(int status, String context) {
        assertTrue(status >= 400 && status < 500 && status != 404 && status != 405,
                context + " must be rejected with 4xx (not 404/405), got " + status);
    }

    private static void assertLoginDenied(MvcResult res, String message) throws Exception {
        int status = res.getResponse().getStatus();
        assertTrue(status < 500 && (status == 200 || (status >= 400 && status != 404 && status != 405)),
                message + " (unexpected status " + status + ")");
        String body = res.getResponse().getContentAsString();
        if (status == 200 || (body != null && body.trim().startsWith("{"))) {
            assertFalse(JSON.readTree(body).path("authenticated").asBoolean(), message);
        }
    }

    private void assertIntrospectInactiveOrForbidden(MockMvc mvc, String clientId, String secret, String token)
            throws Exception {
        MvcResult res = introspectRaw(mvc, basicAuth(clientId, secret), token);
        int status = res.getResponse().getStatus();
        if (status >= 400 && status < 500 && status != 404 && status != 405) {
            return;
        }
        assertEquals(200, status,
                "Expected 4xx (not 404/405) or 200 {\"active\":false} from /oauth2/introspect, got " + status
                        + " body=" + res.getResponse().getContentAsString());
        JsonNode body = JSON.readTree(res.getResponse().getContentAsString());
        assertFalse(body.path("active").asBoolean(),
                "Expected active=false from /oauth2/introspect, got " + body);
    }

    private static void assertNoBcryptHash(String body) {
        assertFalse(body.contains("$2a$") || body.contains("$2b$") || body.contains("$2y$"),
                "Response must never leak BCrypt secret hash: " + body);
    }

    private static void assertNoSecretInClientJson(String body, JsonNode json, String rawSecret) {
        assertNoBcryptHash(body);
        assertFalse(body.contains(rawSecret), "Response must never leak clientSecret");
        if (json.isArray()) {
            for (JsonNode item : json) {
                assertTrue(item.path("clientSecret").isMissingNode() || item.path("clientSecret").isNull(),
                        "List item must omit clientSecret: " + item);
            }
        } else {
            assertTrue(json.path("clientSecret").isMissingNode() || json.path("clientSecret").isNull(),
                    "Client JSON must omit clientSecret: " + json);
        }
    }

    private MvcResult revokeRaw(MockMvc mvc, String basicHeader, String token) throws Exception {
        var req = post("/oauth2/revoke").contentType(MediaType.APPLICATION_FORM_URLENCODED);
        if (basicHeader != null) {
            req.header(HttpHeaders.AUTHORIZATION, basicHeader);
        }
        if (token != null) {
            req.param("token", token);
        }
        return mvc.perform(req).andReturn();
    }

    private static String loginBody(String username, String password, String otp) {
        ObjectNode node = JSON.createObjectNode();
        node.put("username", username);
        if (password != null) {
            node.put("password", password);
        }
        if (otp != null) {
            node.put("otp", otp);
        }
        return node.toString();
    }

    private MvcResult callAuthLogin(MockMvc mvc, String bearerToken, String username, String password, String otp)
            throws Exception {
        var req = post("/v1/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(loginBody(username, password, otp));
        if (bearerToken != null) {
            req.header(HttpHeaders.AUTHORIZATION, "Bearer " + bearerToken);
        }
        return mvc.perform(req).andReturn();
    }

    private MvcResult callOtpValidate(MockMvc mvc, String bearerToken, String username, String otp) throws Exception {
        ObjectNode node = JSON.createObjectNode();
        node.put("username", username);
        node.put("otp", otp);
        var req = post("/v1/api/otp/validate")
                .contentType(MediaType.APPLICATION_JSON)
                .content(node.toString());
        if (bearerToken != null) {
            req.header(HttpHeaders.AUTHORIZATION, "Bearer " + bearerToken);
        }
        return mvc.perform(req).andReturn();
    }

    private MvcResult callOcraValidate(MockMvc mvc, String bearerToken, String username, String challenge, String otp)
            throws Exception {
        ObjectNode node = JSON.createObjectNode();
        node.put("username", username);
        node.put("challenge", challenge);
        node.put("otp", otp);
        var req = post("/v1/api/otp/validate-ocra")
                .contentType(MediaType.APPLICATION_JSON)
                .content(node.toString());
        if (bearerToken != null) {
            req.header(HttpHeaders.AUTHORIZATION, "Bearer " + bearerToken);
        }
        return mvc.perform(req).andReturn();
    }

    private MvcResult callMfaPreAuth(MockMvc mvc, String bearerToken, String username, int otp) throws Exception {
        ObjectNode node = JSON.createObjectNode();
        node.put("username", username);
        node.put("otp", otp);
        var req = post("/v1/api/mfa/preauth")
                .contentType(MediaType.APPLICATION_JSON)
                .content(node.toString());
        if (bearerToken != null) {
            req.header(HttpHeaders.AUTHORIZATION, "Bearer " + bearerToken);
        }
        return mvc.perform(req).andReturn();
    }

    private static Set<String> splitScopes(String spaceDelimited) {
        if (spaceDelimited == null || spaceDelimited.isBlank()) {
            return Set.of();
        }
        return Set.of(spaceDelimited.trim().split("\\s+"));
    }

    private static JsonNode decodeJwtPart(String part) throws Exception {
        byte[] decoded = Base64.getUrlDecoder().decode(part);
        return JSON.readTree(decoded);
    }

    private static RSAPublicKey resolveRsaKeyFromJwks(JsonNode jwks, String kid) throws Exception {
        JsonNode keys = jwks.path("keys");
        assertTrue(keys.isArray() && !keys.isEmpty(), "JWKS must contain at least one JWK in keys[]");
        List<JsonNode> rsaKeys = new ArrayList<>();
        for (JsonNode candidate : keys) {
            for (String privField : List.of("d", "p", "q", "dp", "dq", "qi", "oth")) {
                assertTrue(candidate.path(privField).isMissingNode() || candidate.path(privField).isNull(),
                        "JWKS must never expose private key parameter '" + privField + "'");
            }
            if ("RSA".equals(candidate.path("kty").asText())) {
                rsaKeys.add(candidate);
            }
        }
        assertFalse(rsaKeys.isEmpty(), "JWKS must contain at least one RSA JWK in keys[]");
        JsonNode selected = null;
        if (kid == null || kid.isBlank()) {
            selected = rsaKeys.get(0);
        } else {
            for (JsonNode candidate : rsaKeys) {
                if (kid.equals(candidate.path("kid").asText())) {
                    selected = candidate;
                    break;
                }
            }
            if (selected == null && rsaKeys.size() == 1) {
                selected = rsaKeys.get(0);
            }
        }
        assertNotNull(selected, "No matching RSA JWK found in /oauth2/jwks for kid=" + kid);
        String nB64 = selected.path("n").asText("");
        String eB64 = selected.path("e").asText("");
        assertFalse(nB64.isBlank() || nB64.contains("="), "JWK modulus n must be unpadded Base64url");
        assertFalse(eB64.isBlank() || eB64.contains("="), "JWK exponent e must be unpadded Base64url");
        byte[] nBytes = Base64.getUrlDecoder().decode(nB64);
        byte[] eBytes = Base64.getUrlDecoder().decode(eB64);
        assertTrue(nBytes.length >= 256, "RSA modulus n should be at least 2048 bits, got bytes=" + nBytes.length);
        assertNotEquals(0, nBytes[0], "RFC 7518 6.3.1.1 forbids leading zero-valued octets in JWK n");
        assertNotEquals(0, eBytes[0], "RFC 7518 6.3.1.2 forbids leading zero-valued octets in JWK e");

        RSAPublicKeySpec spec = new RSAPublicKeySpec(new BigInteger(1, nBytes), new BigInteger(1, eBytes));
        return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(spec);
    }

    private static Object getColumnIgnoreCase(Map<String, Object> row, String targetColumn) {
        for (Map.Entry<String, Object> entry : row.entrySet()) {
            if (entry.getKey() != null && entry.getKey().equalsIgnoreCase(targetColumn)) {
                return entry.getValue();
            }
        }
        return null;
    }

    private static boolean rowReferencesClient(Map<String, Object> row, long clientDbId,
                                               String clientId, String clientName) {
        String dbIdStr = Long.toString(clientDbId);
        for (Map.Entry<String, Object> entry : row.entrySet()) {
            String col = entry.getKey() == null ? "" : entry.getKey().toUpperCase(Locale.ROOT);
            Object val = entry.getValue();
            if (val == null || "ID".equals(col) || "USER_ID".equals(col) || "OCCURRED_AT".equals(col)) {
                continue;
            }
            String strVal = val.toString();
            if (strVal.contains(clientId) || strVal.contains(clientName)) {
                return true;
            }
            if (col.contains("CLIENT")) {
                if (val instanceof Number num && num.longValue() == clientDbId) {
                    return true;
                }
                if (dbIdStr.equals(strVal.trim())) {
                    return true;
                }
            }
        }
        return false;
    }

    private static void verifyJwtSignature(String jwt, RSAPublicKey publicKey) throws Exception {
        String[] parts = jwt.split("\\.");
        assertEquals(3, parts.length, "JWT must have 3 dot-separated JWS segments");
        byte[] signingInput = (parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII);
        byte[] sigBytes = Base64.getUrlDecoder().decode(parts[2]);
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(publicKey);
        verifier.update(signingInput);
        assertTrue(verifier.verify(sigBytes), "RS256 JWT signature must verify against /oauth2/jwks public key");
    }

    private static ConfigurableApplicationContext startClusterNode(String dbUrl) {
        return new SpringApplicationBuilder(IamApplication.class).run(
                "--server.port=0",
                "--spring.jmx.enabled=false",
                "--radius.enabled=false",
                "--iam.bootstrap.radius.shared-secret=cluster-oauth-secret",
                "--iam.bootstrap.admin.username=grader-boot-admin",
                "--iam.bootstrap.admin.password=ClusterAdmin!123",
                "--iam.bootstrap.policy.max-failures=2",
                "--iam.bootstrap.policy.lockout-seconds=120",
                "--spring.datasource.url=" + dbUrl,
                "--spring.jpa.hibernate.ddl-auto=update");
    }

    // 1
    @Test
    void verificationEndpointsRejectMissingMalformedAndQueryParamTokensWith401() throws Exception {
        long step = stableCurrentStep();
        String secret = distinctSecret(step);
        createUser("unauth-user", USER_PASS, secret, null);

        String sec = clientSecret("query-check");
        createClient("query-check", sec, ALL_SCOPES);
        String validToken = issueToken("query-check", sec, null);
        String code = otpForStep(secret, step);
        String ocraChallenge = "QH123456";
        String ocraResp = ocraService.generateOcra(secret, ocraChallenge);

        // Missing Authorization header must return 4xx (not 404/405)
        assertRejected4xx(callAuthLogin(mockMvc, null, "unauth-user", USER_PASS, code).getResponse().getStatus(),
                "Missing Authorization header on /v1/api/auth/login");
        assertRejected4xx(callOtpValidate(mockMvc, null, "unauth-user", code).getResponse().getStatus(),
                "Missing Authorization header on /v1/api/otp/validate");
        assertRejected4xx(callOcraValidate(mockMvc, null, "unauth-user", ocraChallenge, ocraResp).getResponse().getStatus(),
                "Missing Authorization header on /v1/api/otp/validate-ocra");
        assertRejected4xx(callMfaPreAuth(mockMvc, null, "unauth-user", Integer.parseInt(code)).getResponse().getStatus(),
                "Missing Authorization header on /v1/api/mfa/preauth");

        // Malformed Bearer headers must return 4xx (e.g., 401 or RFC 6750 400 invalid_request)
        for (String badBearer : List.of("Bearer ", "Bearer", "Bearer not-a-jwt")) {
            int s = mockMvc.perform(post("/v1/api/otp/validate")
                            .header(HttpHeaders.AUTHORIZATION, badBearer)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"username\":\"unauth-user\",\"otp\":\"" + code + "\"}"))
                    .andReturn().getResponse().getStatus();
            assertRejected4xx(s, "Malformed Bearer header '" + badBearer + "'");
        }

        // Non-Bearer Basic headers (including valid client Basic creds) must return 4xx
        for (String badAuth : List.of(
                "Basic " + Base64.getEncoder().encodeToString("x:y".getBytes(StandardCharsets.UTF_8)),
                basicAuth("query-check", sec))) {
            int s = mockMvc.perform(post("/v1/api/otp/validate")
                            .header(HttpHeaders.AUTHORIZATION, badAuth)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"username\":\"unauth-user\",\"otp\":\"" + code + "\"}"))
                    .andReturn().getResponse().getStatus();
            assertRejected4xx(s, "Non-Bearer Authorization header on /v1/api/otp/validate");
        }

        // RFC 6750 Authorization header only: query-string ?access_token= must be rejected with 4xx
        int qAuth = mockMvc.perform(post("/v1/api/auth/login?access_token=" + validToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginBody("unauth-user", USER_PASS, code)))
                .andReturn().getResponse().getStatus();
        assertRejected4xx(qAuth, "Query-param access_token on /v1/api/auth/login");

        int qOtp = mockMvc.perform(post("/v1/api/otp/validate?access_token=" + validToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"unauth-user\",\"otp\":\"" + code + "\"}"))
                .andReturn().getResponse().getStatus();
        assertRejected4xx(qOtp, "Query-param access_token on /v1/api/otp/validate");

        int qOcra = mockMvc.perform(post("/v1/api/otp/validate-ocra?access_token=" + validToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"unauth-user\",\"challenge\":\"" + ocraChallenge + "\",\"otp\":\"" + ocraResp + "\"}"))
                .andReturn().getResponse().getStatus();
        assertRejected4xx(qOcra, "Query-param access_token on /v1/api/otp/validate-ocra");

        int qMfa = mockMvc.perform(post("/v1/api/mfa/preauth?access_token=" + validToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"unauth-user\",\"otp\":" + Integer.parseInt(code) + "}"))
                .andReturn().getResponse().getStatus();
        assertRejected4xx(qMfa, "Query-param access_token on /v1/api/mfa/preauth");
    }

    // 2
    @Test
    void publicSetupAdminLoginBrowserMfaAndJwksRemainAccessibleWithoutBearerToken() throws Exception {
        long step = stableCurrentStep();
        String secret = distinctSecret(step);
        createUser("mfa-browser-user", USER_PASS, secret, null);

        assertEquals(200, mockMvc.perform(get("/mfa")).andReturn().getResponse().getStatus());
        assertEquals(200, mockMvc.perform(post("/mfa")
                        .param("username", "mfa-browser-user")
                        .param("otp", otpForStep(secret, step)))
                .andReturn().getResponse().getStatus());

        MvcResult setupStatus = mockMvc.perform(get("/v1/api/setup/status")).andReturn();
        assertEquals(200, setupStatus.getResponse().getStatus());
        assertTrue(JSON.readTree(setupStatus.getResponse().getContentAsString()).has("setupRequired"));

        MvcResult adminLogin = mockMvc.perform(post("/v1/api/admin/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"grader-boot-admin\",\"password\":\"GraderBootAdm!123\"}"))
                .andReturn();
        String adminBody = adminLogin.getResponse().getContentAsString();
        assertFalse(adminBody.isBlank(), "/v1/api/admin/auth/login must reach AdminAuthController without Bearer auth");
        assertTrue(JSON.readTree(adminBody).has("status"),
                "Expected LoginResponse JSON from /v1/api/admin/auth/login, got: " + adminBody);

        MvcResult jwksRes = mockMvc.perform(get("/oauth2/jwks")).andReturn();
        assertEquals(200, jwksRes.getResponse().getStatus());
        JsonNode jwks = JSON.readTree(jwksRes.getResponse().getContentAsString());
        assertTrue(jwks.path("keys").isArray() && !jwks.path("keys").isEmpty());
    }

    // 3
    @Test
    void scopedBearerTokensEnforceLeastPrivilegeAcrossVerificationEndpoints() throws Exception {
        long step = stableCurrentStep();
        String s1 = distinctSecret(step);
        String s2 = distinctSecret(step);
        String s3 = distinctSecret(step);
        createUser("scope-u1", USER_PASS, s1, null);
        createUser("scope-u2", USER_PASS, s2, null);
        createUser("scope-u3", USER_PASS, s3, null);

        String secLogin = clientSecret("c-login");
        String secOtp = clientSecret("c-otp");
        String secMfa = clientSecret("c-mfa");
        createClient("c-login-only", secLogin, List.of(SCOPE_AUTH_LOGIN));
        createClient("c-otp-only", secOtp, List.of(SCOPE_OTP_VALIDATE));
        createClient("c-mfa-only", secMfa, List.of(SCOPE_MFA_PREAUTH));

        String tokLogin = issueToken("c-login-only", secLogin, null);
        String tokOtp = issueToken("c-otp-only", secOtp, null);
        String tokMfa = issueToken("c-mfa-only", secMfa, null);

        // auth:login client
        MvcResult loginOk = callAuthLogin(mockMvc, tokLogin, "scope-u1", USER_PASS, otpForStep(s1, step - 1));
        assertEquals(200, loginOk.getResponse().getStatus());
        assertTrue(JSON.readTree(loginOk.getResponse().getContentAsString()).path("authenticated").asBoolean());
        assertRejected4xx(callOtpValidate(mockMvc, tokLogin, "scope-u1", otpForStep(s1, step)).getResponse().getStatus(),
                "auth:login token calling /v1/api/otp/validate");
        assertRejected4xx(callOcraValidate(mockMvc, tokLogin, "scope-u1", "CH1",
                ocraService.generateOcra(s1, "CH1")).getResponse().getStatus(),
                "auth:login token calling /v1/api/otp/validate-ocra");
        assertRejected4xx(callMfaPreAuth(mockMvc, tokLogin, "scope-u1",
                Integer.parseInt(otpForStep(s1, step))).getResponse().getStatus(),
                "auth:login token calling /v1/api/mfa/preauth");

        // otp:validate client
        MvcResult totpOk = callOtpValidate(mockMvc, tokOtp, "scope-u2", otpForStep(s2, step - 1));
        assertEquals(200, totpOk.getResponse().getStatus());
        assertTrue(JSON.readTree(totpOk.getResponse().getContentAsString()).path("valid").asBoolean());
        MvcResult ocraOk = callOcraValidate(mockMvc, tokOtp, "scope-u2", "CH22",
                ocraService.generateOcra(s2, "CH22"));
        assertEquals(200, ocraOk.getResponse().getStatus());
        assertTrue(JSON.readTree(ocraOk.getResponse().getContentAsString()).path("valid").asBoolean());
        assertRejected4xx(callAuthLogin(mockMvc, tokOtp, "scope-u2", USER_PASS,
                otpForStep(s2, step)).getResponse().getStatus(),
                "otp:validate token calling /v1/api/auth/login");
        assertRejected4xx(callMfaPreAuth(mockMvc, tokOtp, "scope-u2",
                Integer.parseInt(otpForStep(s2, step))).getResponse().getStatus(),
                "otp:validate token calling /v1/api/mfa/preauth");

        // mfa:preauth client
        MvcResult mfaOk = callMfaPreAuth(mockMvc, tokMfa, "scope-u3", Integer.parseInt(otpForStep(s3, step - 1)));
        assertEquals(200, mfaOk.getResponse().getStatus());
        assertEquals("true", mfaOk.getResponse().getContentAsString().trim());
        assertRejected4xx(callAuthLogin(mockMvc, tokMfa, "scope-u3", USER_PASS,
                otpForStep(s3, step)).getResponse().getStatus(),
                "mfa:preauth token calling /v1/api/auth/login");
        assertRejected4xx(callOtpValidate(mockMvc, tokMfa, "scope-u3",
                otpForStep(s3, step)).getResponse().getStatus(),
                "mfa:preauth token calling /v1/api/otp/validate");
        assertRejected4xx(callOcraValidate(mockMvc, tokMfa, "scope-u3", "CH33",
                ocraService.generateOcra(s3, "CH33")).getResponse().getStatus(),
                "mfa:preauth token calling /v1/api/otp/validate-ocra");
    }

    // 4
    @Test
    void bearerRequestsAreStatelessAndDoNotCreateReusableHttpSession() throws Exception {
        long step = stableCurrentStep();
        String secret = distinctSecret(step);
        createUser("stateless-user", USER_PASS, secret, null);

        String sec = clientSecret("stateless");
        createClient("stateless-client", sec, ALL_SCOPES);
        String token = issueToken("stateless-client", sec, null);

        MockHttpSession session = new MockHttpSession();
        MvcResult first = mockMvc.perform(post("/v1/api/otp/validate")
                        .session(session)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"stateless-user\",\"otp\":\"" + otpForStep(secret, step - 1) + "\"}"))
                .andReturn();
        assertEquals(200, first.getResponse().getStatus());

        var secondReq = post("/v1/api/otp/validate")
                .session(session)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"stateless-user\",\"otp\":\"" + otpForStep(secret, step) + "\"}");
        Cookie[] cookies = first.getResponse().getCookies();
        if (cookies != null && cookies.length > 0) {
            secondReq.cookie(cookies);
        }
        assertRejected4xx(mockMvc.perform(secondReq).andReturn().getResponse().getStatus(),
                "Bearer requests must be stateless and must not populate HttpSession for later headerless calls");
    }

    // 5
    @Test
    void clientBearerTokensAreRejectedWith403OnAdminAndManagementRoutes() throws Exception {
        String sec = clientSecret("full-scope");
        createClient("full-scope-client", sec, ALL_SCOPES);
        String token = issueToken("full-scope-client", sec, null);

        // Unauthenticated client management API returns 4xx
        int unauthClients = mockMvc.perform(get("/v1/api/clients/all")).andReturn().getResponse().getStatus();
        if (unauthClients == 404 || unauthClients == 405) {
            unauthClients = mockMvc.perform(get("/v1/api/clients")).andReturn().getResponse().getStatus();
        }
        assertRejected4xx(unauthClients, "Unauthenticated request to client list route");

        // OAuth2 client Bearer token must be rejected (4xx) on all protected admin routes
        int bearerListStatus = mockMvc.perform(get("/v1/api/clients/all")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andReturn().getResponse().getStatus();
        if (bearerListStatus == 404 || bearerListStatus == 405) {
            bearerListStatus = mockMvc.perform(get("/v1/api/clients")
                            .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                    .andReturn().getResponse().getStatus();
        }
        assertRejected4xx(bearerListStatus, "Bearer token on client list route");

        String escalatedPayload = JSON.writeValueAsString(clientPayload(
                null, "escalated", clientSecret("esc"), "Esc", true, false, null, ALL_SCOPES));
        int bearerCreateStatus = mockMvc.perform(post("/v1/api/clients/create")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(escalatedPayload))
                .andReturn().getResponse().getStatus();
        if (bearerCreateStatus == 404 || bearerCreateStatus == 405) {
            bearerCreateStatus = mockMvc.perform(post("/v1/api/clients")
                            .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(escalatedPayload))
                    .andReturn().getResponse().getStatus();
        }
        assertRejected4xx(bearerCreateStatus, "Bearer token on client create route");

        for (String adminEndpoint : List.of(
                "/v1/api/users/all",
                "/v1/api/admins/all",
                "/v1/api/policies/current",
                "/v1/api/radius-clients/all")) {
            int s = mockMvc.perform(get(adminEndpoint)
                            .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                    .andReturn().getResponse().getStatus();
            assertRejected4xx(s, "Bearer token on " + adminEndpoint);
        }

        int webUsersStatus = mockMvc.perform(get("/users")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andReturn().getResponse().getStatus();
        assertTrue(webUsersStatus == 302
                        || (webUsersStatus >= 400 && webUsersStatus < 500 && webUsersStatus != 404 && webUsersStatus != 405),
                "Admin web page /users must reject OAuth2 client Bearer tokens (302 or 4xx not 404/405), got " + webUsersStatus);
    }

    // 6
    @Test
    @WithMockUser(roles = "ADMIN")
    void clientCrudLifecycleDuplicateRejectionAndSecretOmissionInResponses() throws Exception {
        String rawSecret = clientSecret("crud");
        JsonNode created = createClient(mockMvc, "crud-client", rawSecret, "Partner Portal",
                true, false, AuthMode.PASSWORD_AND_OTP_INLINE,
                List.of(SCOPE_AUTH_LOGIN, SCOPE_OTP_VALIDATE));

        long id = created.get("id").asLong();
        assertTrue(id > 0);
        assertEquals("crud-client", created.get("clientId").asText());
        assertEquals("Partner Portal", created.get("name").asText());
        assertTrue(created.get("enabled").asBoolean());
        assertFalse(created.get("blocked").asBoolean());
        assertEquals("PASSWORD_AND_OTP_INLINE", created.get("authMode").asText());
        assertNoBcryptHash(created.toString());

        // Duplicate clientId must be rejected
        MvcResult dup = createClientRaw(mockMvc, clientPayload(
                null, "crud-client", clientSecret("another"), "Dup", true, false, null, List.of(SCOPE_AUTH_LOGIN)));
        assertRejected4xx(dup.getResponse().getStatus(), "Duplicate clientId creation");

        // Unsupported scope outside {auth:login, otp:validate, mfa:preauth} must be rejected
        MvcResult badScopeRes = createClientRaw(mockMvc, clientPayload(
                null, "bad-scope-client", clientSecret("bad-scope"), "Bad Scope", true, false, null, List.of("admin:all")));
        assertRejected4xx(badScopeRes.getResponse().getStatus(),
                "Creating a client with unknown scope");

        // Creating a client with empty scopes must be rejected
        MvcResult emptyScopeRes = createClientRaw(mockMvc, clientPayload(
                null, "empty-scope-client", clientSecret("empty-scope"), "Empty Scope", true, false, null, List.of()));
        assertRejected4xx(emptyScopeRes.getResponse().getStatus(),
                "Creating a client with empty scopes list");

        // Get by ID and List all must omit secret
        MvcResult getRes = getClientRaw(mockMvc, id);
        assertEquals(200, getRes.getResponse().getStatus());
        String getBody = getRes.getResponse().getContentAsString();
        assertNoSecretInClientJson(getBody, JSON.readTree(getBody), rawSecret);

        MvcResult listRes = getClientsRaw(mockMvc);
        assertEquals(200, listRes.getResponse().getStatus());
        String listBody = listRes.getResponse().getContentAsString();
        assertNoSecretInClientJson(listBody, JSON.readTree(listBody), rawSecret);
        assertTrue(listBody.contains("crud-client"));

        // Update metadata without clientSecret must preserve existing secret and not leak it
        JsonNode updated = updateClient(mockMvc, id, "crud-client", null, "Renamed Portal",
                true, false, null, List.of(SCOPE_OTP_VALIDATE));
        assertEquals("Renamed Portal", updated.get("name").asText());
        assertNoSecretInClientJson(updated.toString(), updated, rawSecret);

        String tokenAfterMetaUpdate = issueToken("crud-client", rawSecret, null);
        assertFalse(tokenAfterMetaUpdate.isBlank());

        // Delete removes client
        MvcResult delRes = deleteClientRaw(mockMvc, id);
        int delStatus = delRes.getResponse().getStatus();
        assertTrue(delStatus >= 200 && delStatus < 300,
                "Expected 2xx deleting client, got " + delStatus);
        int getAfterDeleteStatus = getClientRaw(mockMvc, id).getResponse().getStatus();
        assertTrue(getAfterDeleteStatus == 404 || getAfterDeleteStatus == 410 || getAfterDeleteStatus == 400,
                "Expected 404/410/400 fetching deleted client, got " + getAfterDeleteStatus);
    }

    // 7
    @Test
    void tokenEndpointIssuesValidTokenViaHttpBasicAndSetsNoStoreHeaders() throws Exception {
        String basicSec = clientSecret("basic");
        createClient("basic-client", basicSec, List.of(SCOPE_OTP_VALIDATE));

        // Missing credentials, unknown client, wrong secret, unsupported grant_type
        int noAuthTokenStatus = requestTokenRaw(mockMvc, null, "client_credentials", null)
                .getResponse().getStatus();
        assertRejected4xx(noAuthTokenStatus, "Missing Authorization header on /oauth2/token");
        int unknownClientStatus = requestTokenRaw(mockMvc, basicAuth("no-such-client", basicSec),
                "client_credentials", null).getResponse().getStatus();
        assertTrue(unknownClientStatus >= 400 && unknownClientStatus < 500 && unknownClientStatus != 405,
                "Unknown client on /oauth2/token must return 4xx (not 405), got " + unknownClientStatus);
        int badSecretStatus = requestTokenRaw(mockMvc, basicAuth("basic-client", "WrongSecret"),
                "client_credentials", null).getResponse().getStatus();
        assertRejected4xx(badSecretStatus, "Wrong secret on /oauth2/token");

        int missingGrantStatus = requestTokenRaw(mockMvc, basicAuth("basic-client", basicSec),
                null, null).getResponse().getStatus();
        assertRejected4xx(missingGrantStatus, "Missing grant_type on /oauth2/token");

        int badGrantStatus = requestTokenRaw(mockMvc, basicAuth("basic-client", basicSec),
                "password", null).getResponse().getStatus();
        assertRejected4xx(badGrantStatus, "Unsupported grant_type on /oauth2/token");

        int jsonCtStatus = mockMvc.perform(post("/oauth2/token")
                        .header(HttpHeaders.AUTHORIZATION, basicAuth("basic-client", basicSec))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"grant_type\":\"client_credentials\"}"))
                .andReturn().getResponse().getStatus();
        assertRejected4xx(jsonCtStatus, "POST /oauth2/token with application/json Content-Type");

        MvcResult ok = requestTokenRaw(mockMvc, basicAuth("basic-client", basicSec),
                "client_credentials", null);
        assertEquals(200, ok.getResponse().getStatus());
        String cacheControl = ok.getResponse().getHeader(HttpHeaders.CACHE_CONTROL);
        assertNotNull(cacheControl, "RFC 6749 5.1 requires Cache-Control: no-store");
        assertTrue(cacheControl.toLowerCase(Locale.ROOT).contains("no-store"),
                "Cache-Control must contain no-store, got: " + cacheControl);

        JsonNode body = JSON.readTree(ok.getResponse().getContentAsString());
        assertFalse(body.path("access_token").asText("").isBlank());
        String tokenType = body.path("token_type").asText("");
        assertTrue("bearer".equalsIgnoreCase(tokenType),
                "RFC 6749 5.1 requires case-insensitive Bearer token_type, got: " + tokenType);
        assertTrue(body.path("expires_in").asLong(0) > 0, "expires_in must be positive");
    }

    // 8
    @Test
    void tokenEndpointDefaultsOmittedScopeNarrowsSubsetAndRejectsUngrantedScope() throws Exception {
        long step = stableCurrentStep();
        String secret = distinctSecret(step);
        createUser("scope-grant-user", USER_PASS, secret, null);

        String twoScopeSec = clientSecret("two-scope");
        createClient("two-scope", twoScopeSec, List.of(SCOPE_AUTH_LOGIN, SCOPE_OTP_VALIDATE));

        // Omitting scope defaults to client's configured scopes
        String defaultToken = issueToken("two-scope", twoScopeSec, null);
        assertEquals(200, callAuthLogin(mockMvc, defaultToken, "scope-grant-user", USER_PASS,
                otpForStep(secret, step - 1)).getResponse().getStatus());
        assertEquals(200, callOtpValidate(mockMvc, defaultToken, "scope-grant-user",
                otpForStep(secret, step)).getResponse().getStatus());

        // Narrowing to subset works and restricts endpoint access
        String narrowedToken = issueToken("two-scope", twoScopeSec, SCOPE_OTP_VALIDATE);
        assertEquals(200, callOtpValidate(mockMvc, narrowedToken, "scope-grant-user",
                otpForStep(secret, step + 1)).getResponse().getStatus());
        assertRejected4xx(callAuthLogin(mockMvc, narrowedToken, "scope-grant-user", USER_PASS,
                otpForStep(secret, step)).getResponse().getStatus(),
                "Out-of-scope /v1/api/auth/login with narrowed token");

        // Requesting ungranted or unknown scope fails with 4xx
        MvcResult escalated = requestTokenRaw(mockMvc, basicAuth("two-scope", twoScopeSec),
                "client_credentials", SCOPE_AUTH_LOGIN + " " + SCOPE_MFA_PREAUTH);
        assertRejected4xx(escalated.getResponse().getStatus(),
                "Requesting ungranted scope on /oauth2/token");
        assertRejected4xx(requestTokenRaw(mockMvc, basicAuth("two-scope", twoScopeSec),
                "client_credentials", "admin:all").getResponse().getStatus(),
                "Requesting unknown scope on /oauth2/token");
    }

    // 9
    @Test
    void jwtHeaderAndRfc9068ClaimsContainRequiredMetadata() throws Exception {
        String sec = clientSecret("claims");
        createClient("claims-client", sec, List.of(SCOPE_AUTH_LOGIN, SCOPE_OTP_VALIDATE));

        String token1 = issueToken("claims-client", sec, null);
        String token2 = issueToken("claims-client", sec, SCOPE_OTP_VALIDATE);

        assertFalse(token1.contains("=") || token2.contains("="),
                "RFC 7515 2 requires unpadded Base64url JWS segments");
        String[] parts1 = token1.split("\\.");
        String[] parts2 = token2.split("\\.");
        assertEquals(3, parts1.length);
        assertEquals(3, parts2.length);

        JsonNode hdr = decodeJwtPart(parts1[0]);
        assertEquals("RS256", hdr.path("alg").asText());
        if (hdr.hasNonNull("typ")) {
            String typ = hdr.get("typ").asText().toLowerCase(Locale.ROOT);
            assertTrue(Set.of("at+jwt", "application/at+jwt", "jwt").contains(typ),
                    "Unexpected JWT typ header: " + typ);
        }

        JsonNode p1 = decodeJwtPart(parts1[1]);
        JsonNode p2 = decodeJwtPart(parts2[1]);
        assertFalse(p1.path("iss").asText("").isBlank(), "iss claim must be present");
        assertFalse(p1.path("sub").asText("").isBlank(), "sub claim must be present");
        assertEquals("claims-client", p1.path("client_id").asText());
        assertTrue(p1.path("iat").isNumber() && p1.path("exp").isNumber());
        assertTrue(p1.path("exp").asLong() > p1.path("iat").asLong());

        String jti1 = p1.path("jti").asText("");
        String jti2 = p2.path("jti").asText("");
        assertFalse(jti1.isBlank() || jti2.isBlank(), "jti must be non-blank");
        assertNotEquals(jti1, jti2, "Each issued JWT must have a unique jti");

        assertTrue(p1.path("scope").isTextual(), "RFC 9068 scope claim must be a space-delimited string");
        assertEquals(Set.of(SCOPE_AUTH_LOGIN, SCOPE_OTP_VALIDATE), splitScopes(p1.path("scope").asText()));
        assertEquals(Set.of(SCOPE_OTP_VALIDATE), splitScopes(p2.path("scope").asText()));
    }

    // 10
    @Test
    void jwksExposesRfc7518UnsignedRsaKeyThatVerifiesIssuedJwtSignatures() throws Exception {
        String sec = clientSecret("jwks");
        createClient("jwks-client", sec, List.of(SCOPE_OTP_VALIDATE));
        String jwt = issueToken("jwks-client", sec, null);
        String[] parts = jwt.split("\\.");
        assertEquals(3, parts.length);
        String kid = decodeJwtPart(parts[0]).path("kid").asText(null);

        MvcResult jwksRes = mockMvc.perform(get("/oauth2/jwks")).andReturn();
        assertEquals(200, jwksRes.getResponse().getStatus());
        JsonNode jwks = JSON.readTree(jwksRes.getResponse().getContentAsString());

        RSAPublicKey publicKey = resolveRsaKeyFromJwks(jwks, kid);
        verifyJwtSignature(jwt, publicKey);
    }

    // 11
    @Test
    void tamperedAndAlgNoneJwtTokensAreRejectedAcrossApiAndIntrospection() throws Exception {
        long step = stableCurrentStep();
        String secret = distinctSecret(step);
        createUser("tamper-user", USER_PASS, secret, null);
        String sec = clientSecret("tamper");
        createClient("tamper-client", sec, List.of(SCOPE_OTP_VALIDATE));

        String valid = issueToken("tamper-client", sec, SCOPE_OTP_VALIDATE);
        String[] parts = valid.split("\\.");
        assertEquals(3, parts.length);

        // Escalate scope in payload while reusing original signature
        ObjectNode escalatedPayload = (ObjectNode) decodeJwtPart(parts[1]);
        escalatedPayload.put("scope", SCOPE_AUTH_LOGIN + " " + SCOPE_OTP_VALIDATE + " " + SCOPE_MFA_PREAUTH);
        String forgedPayloadB64 = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(JSON.writeValueAsBytes(escalatedPayload));
        String payloadTamperedJwt = parts[0] + "." + forgedPayloadB64 + "." + parts[2];

        // Corrupt signature segment deterministically in underlying signature bytes
        byte[] sigBytes = Base64.getUrlDecoder().decode(parts[2]);
        sigBytes[0] ^= 0x01;
        String sigTamperedJwt = parts[0] + "." + parts[1] + "."
                + Base64.getUrlEncoder().withoutPadding().encodeToString(sigBytes);

        // Unsigned alg=none token
        String algNoneHeader = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"none\",\"typ\":\"at+jwt\"}".getBytes(StandardCharsets.UTF_8));
        String algNoneJwt = algNoneHeader + "." + parts[1] + ".";

        String code = otpForStep(secret, step);
        for (String badJwt : List.of(payloadTamperedJwt, sigTamperedJwt, algNoneJwt)) {
            assertRejected4xx(callOtpValidate(mockMvc, badJwt, "tamper-user", code).getResponse().getStatus(),
                    "Tampered or alg=none JWT on /v1/api/otp/validate");
            assertRejected4xx(callAuthLogin(mockMvc, badJwt, "tamper-user", USER_PASS, code).getResponse().getStatus(),
                    "Tampered or alg=none JWT on /v1/api/auth/login");
            assertIntrospectInactiveOrForbidden(mockMvc, "tamper-client", sec, badJwt);
        }
    }

    // 12
    @Test
    void introspectionRequiresHttpBasicClientAuthAndReportsTokenState() throws Exception {
        String sec = clientSecret("intro");
        createClient("intro-client", sec, List.of(SCOPE_OTP_VALIDATE, SCOPE_MFA_PREAUTH));
        String token = issueToken("intro-client", sec, SCOPE_OTP_VALIDATE);

        int noAuthIntroStatus = introspectRaw(mockMvc, null, token).getResponse().getStatus();
        assertRejected4xx(noAuthIntroStatus, "Missing Authorization header on /oauth2/introspect");
        assertRejected4xx(introspectRaw(mockMvc, basicAuth("intro-client", "WrongSec"), token)
                .getResponse().getStatus(), "Wrong client secret on /oauth2/introspect");

        JsonNode active = introspect(mockMvc, "intro-client", sec, token);
        assertTrue(active.path("active").asBoolean());
        assertEquals("intro-client", active.path("client_id").asText());
        assertEquals(Set.of(SCOPE_OTP_VALIDATE), splitScopes(active.path("scope").asText()));

        assertIntrospectInactiveOrForbidden(mockMvc, "intro-client", sec, "not.a.valid.token");
    }

    // 13
    @Test
    void accessTokenRevocationInvalidatesOwnTokenWhilePreservingOtherClientsTokens() throws Exception {
        long step = stableCurrentStep();
        String secret = distinctSecret(step);
        createUser("rev-user", USER_PASS, secret, null);

        String secA = clientSecret("rev-a");
        String secB = clientSecret("rev-b");
        createClient("rev-client-a", secA, List.of(SCOPE_AUTH_LOGIN));
        createClient("rev-client-b", secB, List.of(SCOPE_OTP_VALIDATE));

        String tokenA = issueToken("rev-client-a", secA, null);
        String tokenB = issueToken("rev-client-b", secB, null);

        int noAuthRevokeStatus = revokeRaw(mockMvc, null, tokenB).getResponse().getStatus();
        assertRejected4xx(noAuthRevokeStatus, "Missing Authorization header on /oauth2/revoke");
        assertRejected4xx(revokeRaw(mockMvc, basicAuth("rev-client-b", "WrongB"), tokenB).getResponse().getStatus(),
                "Wrong client secret on /oauth2/revoke");

        // Client A attempts to revoke Client B's token: Client B's token must stay active
        MvcResult crossRevoke = revokeRaw(mockMvc, basicAuth("rev-client-a", secA), tokenB);
        assertFalse(crossRevoke.getResponse().getContentAsString().contains("unsupported_token_type"));
        assertEquals(200, callOtpValidate(mockMvc, tokenB, "rev-user",
                otpForStep(secret, step - 1)).getResponse().getStatus());
        assertTrue(introspect(mockMvc, "rev-client-b", secB, tokenB).path("active").asBoolean());

        // RFC 7009 2.2: revoking an invalid/unknown token returns 200/204
        int unknownRevokeStatus = revokeRaw(mockMvc, basicAuth("rev-client-b", secB), "unknown.nonexistent.token")
                .getResponse().getStatus();
        assertTrue(unknownRevokeStatus == 200 || unknownRevokeStatus == 204,
                "Expected 200/204 revoking unknown token, got " + unknownRevokeStatus);

        // Client B revokes its own token (must work and be idempotent)
        int ownRevoke1 = revokeRaw(mockMvc, basicAuth("rev-client-b", secB), tokenB).getResponse().getStatus();
        assertTrue(ownRevoke1 == 200 || ownRevoke1 == 204,
                "Expected 200/204 revoking own token, got " + ownRevoke1);
        int ownRevoke2 = revokeRaw(mockMvc, basicAuth("rev-client-b", secB), tokenB).getResponse().getStatus();
        assertTrue(ownRevoke2 == 200 || ownRevoke2 == 204,
                "Expected idempotent 200/204 revoking own token, got " + ownRevoke2);

        assertRejected4xx(callOtpValidate(mockMvc, tokenB, "rev-user",
                otpForStep(secret, step)).getResponse().getStatus(),
                "Revoked tokenB on /v1/api/otp/validate");
        assertIntrospectInactiveOrForbidden(mockMvc, "rev-client-b", secB, tokenB);

        // Client A's token remains active
        assertEquals(200, callAuthLogin(mockMvc, tokenA, "rev-user", USER_PASS,
                otpForStep(secret, step)).getResponse().getStatus());
    }

    // 14
    @Test
    @WithMockUser(roles = "ADMIN")
    void disablingOrBlockingClientImmediatelyInvalidatesIssuedTokens() throws Exception {
        long step = stableCurrentStep();
        String secret = distinctSecret(step);
        createUser("status-user", USER_PASS, secret, null);

        String disSec = clientSecret("dis");
        String blkSec = clientSecret("blk");
        JsonNode c1 = createClient("disable-client", disSec, List.of(SCOPE_OTP_VALIDATE));
        JsonNode c2 = createClient("block-client", blkSec, List.of(SCOPE_OTP_VALIDATE));

        String t1 = issueToken("disable-client", disSec, null);
        String t2 = issueToken("block-client", blkSec, null);

        // Disable client 1
        updateClient(mockMvc, c1.get("id").asLong(), "disable-client", null, "Client 1",
                false, false, null, List.of(SCOPE_OTP_VALIDATE));
        assertRejected4xx(callOtpValidate(mockMvc, t1, "status-user",
                otpForStep(secret, step)).getResponse().getStatus(),
                "Disabled client token on /v1/api/otp/validate");
        assertIntrospectInactiveOrForbidden(mockMvc, "block-client", blkSec, t1);
        assertRejected4xx(requestTokenRaw(mockMvc, basicAuth("disable-client", disSec),
                "client_credentials", null).getResponse().getStatus(),
                "Disabled client on /oauth2/token");

        // Block client 2
        updateClient(mockMvc, c2.get("id").asLong(), "block-client", null, "Client 2",
                true, true, null, List.of(SCOPE_OTP_VALIDATE));
        assertRejected4xx(callOtpValidate(mockMvc, t2, "status-user",
                otpForStep(secret, step)).getResponse().getStatus(),
                "Blocked client token on /v1/api/otp/validate");
        assertRejected4xx(requestTokenRaw(mockMvc, basicAuth("block-client", blkSec),
                "client_credentials", null).getResponse().getStatus(),
                "Blocked client on /oauth2/token");
    }

    // 15
    @Test
    @WithMockUser(roles = "ADMIN")
    void rotatingClientSecretSwitchesCredentialsAndInvalidatesPriorTokens() throws Exception {
        long step = stableCurrentStep();
        String secret = distinctSecret(step);
        createUser("rotate-user", USER_PASS, secret, null);

        String oldSec = clientSecret("rot-old");
        String newSec = clientSecret("rot-new");
        JsonNode created = createClient("rotate-client", oldSec, List.of(SCOPE_OTP_VALIDATE));
        long clientPk = created.get("id").asLong();

        String oldToken = issueToken("rotate-client", oldSec, null);
        assertEquals(200, callOtpValidate(mockMvc, oldToken, "rotate-user",
                otpForStep(secret, step - 1)).getResponse().getStatus());

        updateClient(mockMvc, clientPk, "rotate-client", newSec, "Rotated Client",
                true, false, null, List.of(SCOPE_OTP_VALIDATE));

        // Old secret and pre-rotation token must immediately fail
        assertRejected4xx(requestTokenRaw(mockMvc, basicAuth("rotate-client", oldSec),
                "client_credentials", null).getResponse().getStatus(),
                "Old rotated secret on /oauth2/token");
        assertRejected4xx(callOtpValidate(mockMvc, oldToken, "rotate-user",
                otpForStep(secret, step)).getResponse().getStatus(),
                "Pre-rotation token on /v1/api/otp/validate");
        assertFalse(introspect(mockMvc, "rotate-client", newSec, oldToken).path("active").asBoolean());

        // New secret works and produces an accepted token
        String newToken = issueToken("rotate-client", newSec, null);
        assertEquals(200, callOtpValidate(mockMvc, newToken, "rotate-user",
                otpForStep(secret, step)).getResponse().getStatus());
        assertTrue(introspect(mockMvc, "rotate-client", newSec, newToken).path("active").asBoolean());
    }

    // 16
    @Test
    @WithMockUser(roles = "ADMIN")
    void deletingClientImmediatelyInvalidatesIssuedTokens() throws Exception {
        long step = stableCurrentStep();
        String secret = distinctSecret(step);
        createUser("delete-client-user", USER_PASS, secret, null);

        String delSec = clientSecret("del");
        String helpSec = clientSecret("help");
        JsonNode created = createClient("del-client", delSec, List.of(SCOPE_OTP_VALIDATE));
        JsonNode introspector = createClient("helper-intro", helpSec, List.of(SCOPE_OTP_VALIDATE));
        assertTrue(introspector.hasNonNull("id"));

        String issued = issueToken("del-client", delSec, null);
        int delStatus = deleteClientRaw(mockMvc, created.get("id").asLong()).getResponse().getStatus();
        assertTrue(delStatus >= 200 && delStatus < 300,
                "Expected 2xx deleting client, got " + delStatus);

        assertRejected4xx(callOtpValidate(mockMvc, issued, "delete-client-user",
                otpForStep(secret, step)).getResponse().getStatus(),
                "Deleted client token on /v1/api/otp/validate");
        assertIntrospectInactiveOrForbidden(mockMvc, "helper-intro", helpSec, issued);
        int deletedTokenStatus = requestTokenRaw(mockMvc, basicAuth("del-client", delSec),
                "client_credentials", null).getResponse().getStatus();
        assertTrue(deletedTokenStatus >= 400 && deletedTokenStatus < 500 && deletedTokenStatus != 405,
                "Deleted client on /oauth2/token must return 4xx (not 405), got " + deletedTokenStatus);
    }

    // 17
    @Test
    void clientBruteForceFailuresEnforceSecurityPolicyLockoutAcrossConcurrentAttempts() throws Exception {
        // Part A: policy maxFailures=2 locks out client from further token issuance
        configurePolicy(2, 120, 300, AuthMode.PASSWORD_AND_OTP);
        String secA = clientSecret("bf-a");
        createClient("bf-client-a", secA, List.of(SCOPE_OTP_VALIDATE));
        String tokenBeforeLock = issueToken("bf-client-a", secA, null);
        assertFalse(tokenBeforeLock.isBlank());

        requestTokenRaw(mockMvc, basicAuth("bf-client-a", "Wrong1"), "client_credentials", null);
        requestTokenRaw(mockMvc, basicAuth("bf-client-a", "Wrong2"), "client_credentials", null);

        int afterLockTokenStatus = requestTokenRaw(mockMvc, basicAuth("bf-client-a", secA),
                "client_credentials", null).getResponse().getStatus();
        assertRejected4xx(afterLockTokenStatus,
                "Locked-out client must be denied new tokens even with the right secret");

        // Part B: 4 concurrent failures reach policy threshold maxFailures=4 atomically
        configurePolicy(4, 120, 300, AuthMode.PASSWORD_AND_OTP);
        String secConc = clientSecret("bf-conc");
        createClient("bf-client-conc", secConc, List.of(SCOPE_OTP_VALIDATE));
        ExecutorService pool = Executors.newFixedThreadPool(4);
        CountDownLatch ready = new CountDownLatch(4);
        CountDownLatch start = new CountDownLatch(1);
        try {
            List<Future<Integer>> futures = new ArrayList<>();
            for (int i = 0; i < 4; i++) {
                final int idx = i;
                Callable<Integer> task = () -> {
                    ready.countDown();
                    assertTrue(start.await(5, TimeUnit.SECONDS));
                    return requestTokenRaw(mockMvc, basicAuth("bf-client-conc", "Wrong-" + idx),
                            "client_credentials", null).getResponse().getStatus();
                };
                futures.add(pool.submit(task));
            }
            assertTrue(ready.await(5, TimeUnit.SECONDS));
            start.countDown();
            for (Future<Integer> f : futures) {
                assertRejected4xx(f.get(10, TimeUnit.SECONDS),
                        "Concurrent wrong-secret attempt on /oauth2/token");
            }
        } finally {
            pool.shutdownNow();
        }

        assertRejected4xx(requestTokenRaw(mockMvc, basicAuth("bf-client-conc", secConc),
                "client_credentials", null).getResponse().getStatus(),
                "Concurrent wrong-secret attempts must lock out client at SecurityPolicy.maxFailures without lost updates");
    }

    // 18
    @Test
    @WithMockUser(roles = "ADMIN")
    void unblockingLockedClientClearsActiveBruteForceLockout() throws Exception {
        long step = stableCurrentStep();
        String secret = distinctSecret(step);
        createUser("unblock-user", USER_PASS, secret, null);

        configurePolicy(2, 300, 300, AuthMode.PASSWORD_AND_OTP);
        String sec = clientSecret("unblock");
        JsonNode created = createClient("unblock-client", sec, List.of(SCOPE_OTP_VALIDATE));
        long pk = created.get("id").asLong();

        requestTokenRaw(mockMvc, basicAuth("unblock-client", "Bad1"), "client_credentials", null);
        requestTokenRaw(mockMvc, basicAuth("unblock-client", "Bad2"), "client_credentials", null);
        assertRejected4xx(requestTokenRaw(mockMvc, basicAuth("unblock-client", sec),
                "client_credentials", null).getResponse().getStatus(),
                "Locked-out client prior to unblock on /oauth2/token");

        // Setting blocked=false via PUT /v1/api/clients/{id} must clear active brute-force lockout
        updateClient(mockMvc, pk, "unblock-client", null, "Unblocked",
                true, false, null, List.of(SCOPE_OTP_VALIDATE));

        String recoveredToken = issueToken("unblock-client", sec, null);
        assertEquals(200, callOtpValidate(mockMvc, recoveredToken, "unblock-user",
                otpForStep(secret, step)).getResponse().getStatus());
    }

    // 19
    @Test
    void perClientAuthModeOverridesDefaultModeForLoginRequests() throws Exception {
        long step = stableCurrentStep();
        String secret = distinctSecret(step);
        createUser("mode-default-pw", USER_PASS, null, null);
        createUser("mode-default-mfa", USER_PASS, secret, null);

        String pwSec = clientSecret("pw-only");
        String inlSec = clientSecret("inline");
        String otpSec = clientSecret("otp-only");
        createClient(mockMvc, "c-pw-only", pwSec, "PW Only", true, false,
                AuthMode.PASSWORD_ONLY, List.of(SCOPE_AUTH_LOGIN));
        createClient(mockMvc, "c-inline", inlSec, "Inline", true, false,
                AuthMode.PASSWORD_AND_OTP_INLINE, List.of(SCOPE_AUTH_LOGIN));
        createClient(mockMvc, "c-otp-only", otpSec, "OTP Only", true, false,
                AuthMode.OTP_ONLY, List.of(SCOPE_AUTH_LOGIN));

        String tokPw = issueToken("c-pw-only", pwSec, null);
        String tokInline = issueToken("c-inline", inlSec, null);
        String tokOtp = issueToken("c-otp-only", otpSec, null);

        // PASSWORD_ONLY client allows user with null authMode using password only
        MvcResult r1 = callAuthLogin(mockMvc, tokPw, "mode-default-pw", USER_PASS, null);
        assertEquals(200, r1.getResponse().getStatus());
        assertTrue(JSON.readTree(r1.getResponse().getContentAsString()).path("authenticated").asBoolean());

        // PASSWORD_AND_OTP_INLINE client splits trailing 6 digits of password
        MvcResult r2 = callAuthLogin(mockMvc, tokInline, "mode-default-mfa",
                USER_PASS + otpForStep(secret, step - 1), null);
        assertEquals(200, r2.getResponse().getStatus());
        assertTrue(JSON.readTree(r2.getResponse().getContentAsString()).path("authenticated").asBoolean());

        // OTP_ONLY client authenticates with OTP and no password
        MvcResult r3 = callAuthLogin(mockMvc, tokOtp, "mode-default-mfa", null, otpForStep(secret, step));
        assertEquals(200, r3.getResponse().getStatus());
        assertTrue(JSON.readTree(r3.getResponse().getContentAsString()).path("authenticated").asBoolean());
    }

    // 20
    @Test
    void passwordOnlyClientDoesNotDowngradeExplicitMfaUser() throws Exception {
        long step = stableCurrentStep();
        String sec1 = distinctSecret(step);
        String sec2 = distinctSecret(step);
        createUser("strict-mfa-user", USER_PASS, sec1, AuthMode.PASSWORD_AND_OTP);
        createUser("strict-otp-user", USER_PASS, sec2, AuthMode.OTP_ONLY);

        String downSec = clientSecret("down");
        createClient(mockMvc, "downgrade-try", downSec, "Legacy App", true, false,
                AuthMode.PASSWORD_ONLY, List.of(SCOPE_AUTH_LOGIN));
        String tokPwOnly = issueToken("downgrade-try", downSec, null);

        // User with explicit PASSWORD_AND_OTP must not authenticate with password alone
        MvcResult noOtp = callAuthLogin(mockMvc, tokPwOnly, "strict-mfa-user", USER_PASS, null);
        assertLoginDenied(noOtp, "PASSWORD_ONLY client must not downgrade an explicit PASSWORD_AND_OTP user");

        MvcResult withOtp = callAuthLogin(mockMvc, tokPwOnly, "strict-mfa-user", USER_PASS, otpForStep(sec1, step));
        assertEquals(200, withOtp.getResponse().getStatus());
        assertTrue(JSON.readTree(withOtp.getResponse().getContentAsString()).path("authenticated").asBoolean());

        // User with explicit OTP_ONLY must not authenticate via password on PASSWORD_ONLY client
        MvcResult otpUserPwAttempt = callAuthLogin(mockMvc, tokPwOnly, "strict-otp-user", USER_PASS, null);
        assertLoginDenied(otpUserPwAttempt, "PASSWORD_ONLY client must not downgrade an explicit OTP_ONLY user");
    }

    // 21
    @Test
    void auditLogRecordsClientEventsAndVerificationAttribution() throws Exception {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String auditClientId = "cid_" + suffix;
        String auditClientName = "Billing Gateway " + suffix;
        String auditSec = clientSecret("audit");
        JsonNode created = createClient(mockMvc, auditClientId, auditSec, auditClientName,
                true, false, null, ALL_SCOPES);
        long clientDbId = created.get("id").asLong();

        Set<Long> beforeIds = new HashSet<>();
        for (Map<String, Object> row : jdbcTemplate.queryForList("SELECT * FROM auth_audit_logs")) {
            Object idVal = getColumnIgnoreCase(row, "ID");
            if (idVal instanceof Number num) {
                beforeIds.add(num.longValue());
            }
        }

        String token = issueToken(auditClientId, auditSec, null);
        assertFalse(token.isBlank());
        int failStatus = requestTokenRaw(mockMvc, basicAuth(auditClientId, "WrongAuditSec"),
                "client_credentials", null).getResponse().getStatus();
        assertRejected4xx(failStatus, "Failed client auth for audit");

        List<Map<String, Object>> newRows = jdbcTemplate.queryForList("SELECT * FROM auth_audit_logs").stream()
                .filter(row -> {
                    Object idVal = getColumnIgnoreCase(row, "ID");
                    return !(idVal instanceof Number num) || !beforeIds.contains(num.longValue());
                })
                .toList();

        boolean hasClientSuccess = newRows.stream().anyMatch(row -> {
            Object outcome = getColumnIgnoreCase(row, "OUTCOME");
            return outcome != null
                    && "SUCCESS".equalsIgnoreCase(outcome.toString())
                    && rowReferencesClient(row, clientDbId, auditClientId, auditClientName);
        });
        boolean hasClientFailure = newRows.stream().anyMatch(row -> {
            Object outcome = getColumnIgnoreCase(row, "OUTCOME");
            return outcome != null
                    && ("FAILURE".equalsIgnoreCase(outcome.toString()) || "LOCKED".equalsIgnoreCase(outcome.toString()))
                    && rowReferencesClient(row, clientDbId, auditClientId, auditClientName);
        });

        assertTrue(hasClientSuccess, "Audit log must record successful OAuth2 client authentication");
        assertTrue(hasClientFailure, "Audit log must record failed OAuth2 client authentication");
    }

    // 22
    @Test
    void multiNodeClusterSharesSigningKeysClientsAndPropagatesInvalidations() throws Exception {
        String dbUrl = "jdbc:h2:mem:oauthcluster_" + UUID.randomUUID().toString().replace("-", "") + ";DB_CLOSE_DELAY=-1";
        String isolatedDbUrl = "jdbc:h2:mem:oauthisolated_" + UUID.randomUUID().toString().replace("-", "") + ";DB_CLOSE_DELAY=-1";
        try (ConfigurableApplicationContext node1 = startClusterNode(dbUrl);
             ConfigurableApplicationContext node2 = startClusterNode(dbUrl);
             ConfigurableApplicationContext isolatedNode = startClusterNode(isolatedDbUrl)) {

            MockMvc mvc1 = MockMvcBuilders.webAppContextSetup((WebApplicationContext) node1).apply(springSecurity()).build();
            MockMvc mvc2 = MockMvcBuilders.webAppContextSetup((WebApplicationContext) node2).apply(springSecurity()).build();
            MockMvc isolatedMvc = MockMvcBuilders.webAppContextSetup((WebApplicationContext) isolatedNode).apply(springSecurity()).build();

            long step = stableCurrentStep();
            String userSecret = distinctSecret(step);
            node1.getBean(UserService.class).saveUser(User.builder()
                    .username("cluster-u1")
                    .password(USER_PASS)
                    .secret(userSecret)
                    .build());
            isolatedNode.getBean(UserService.class).saveUser(User.builder()
                    .username("cluster-u1")
                    .password(USER_PASS)
                    .secret(userSecret)
                    .build());

            String cSec1 = clientSecret("cluster-1");
            String cSec2 = clientSecret("cluster-2");
            JsonNode client = createClient(mvc1, "cluster-client", cSec1, "Cluster Gateway",
                    true, false, null, List.of(SCOPE_OTP_VALIDATE));
            long clientPk = client.get("id").asLong();

            // Token minted on node1 verifies against node2 JWKS, works on node2, and is rejected on isolatedNode
            String t1 = issueToken(mvc1, "cluster-client", cSec1, null);
            String kid1 = decodeJwtPart(t1.split("\\.")[0]).path("kid").asText(null);
            JsonNode jwks2 = JSON.readTree(mvc2.perform(get("/oauth2/jwks")).andReturn().getResponse().getContentAsString());
            verifyJwtSignature(t1, resolveRsaKeyFromJwks(jwks2, kid1));

            assertEquals(200, callOtpValidate(mvc2, t1, "cluster-u1",
                    otpForStep(userSecret, step - 1)).getResponse().getStatus());
            assertTrue(introspect(mvc2, "cluster-client", cSec1, t1).path("active").asBoolean());
            assertRejected4xx(callOtpValidate(isolatedMvc, t1, "cluster-u1",
                    otpForStep(userSecret, step - 1)).getResponse().getStatus(),
                    "Token minted for cluster DB on isolated node");

            // Revocation on node1 invalidates immediately on node2
            int clusterRevokeStatus = revokeRaw(mvc1, basicAuth("cluster-client", cSec1), t1).getResponse().getStatus();
            assertTrue(clusterRevokeStatus == 200 || clusterRevokeStatus == 204,
                    "Expected 200/204 revoking token on node1, got " + clusterRevokeStatus);
            assertRejected4xx(callOtpValidate(mvc2, t1, "cluster-u1",
                    otpForStep(userSecret, step)).getResponse().getStatus(),
                    "Revoked token on cluster node2");
            assertIntrospectInactiveOrForbidden(mvc2, "cluster-client", cSec1, t1);

            // Token minted on node2 verifies against node1 JWKS, and secret rotation on node1 invalidates it on node2
            String t2 = issueToken(mvc2, "cluster-client", cSec1, null);
            String kid2 = decodeJwtPart(t2.split("\\.")[0]).path("kid").asText(null);
            JsonNode jwks1 = JSON.readTree(mvc1.perform(get("/oauth2/jwks")).andReturn().getResponse().getContentAsString());
            verifyJwtSignature(t2, resolveRsaKeyFromJwks(jwks1, kid2));

            updateClient(mvc1, clientPk, "cluster-client", cSec2, "Cluster Gateway",
                    true, false, null, List.of(SCOPE_OTP_VALIDATE));
            assertRejected4xx(callOtpValidate(mvc2, t2, "cluster-u1",
                    otpForStep(userSecret, step)).getResponse().getStatus(),
                    "Pre-rotation token on cluster node2");
            assertIntrospectInactiveOrForbidden(mvc2, "cluster-client", cSec2, t2);

            // Disable on node2 invalidates node1-issued token on node1
            String t3 = issueToken(mvc1, "cluster-client", cSec2, null);
            updateClient(mvc2, clientPk, "cluster-client", null, "Cluster Gateway",
                    false, false, null, List.of(SCOPE_OTP_VALIDATE));
            assertRejected4xx(callOtpValidate(mvc1, t3, "cluster-u1",
                    otpForStep(userSecret, step)).getResponse().getStatus(),
                    "Disabled client token on cluster node1");
        }
    }

    // 23
    @Test
    @WithMockUser(roles = "ADMIN")
    void deletedAndRecreatedClientIdDoesNotResurrectOldOrRevokedTokens() throws Exception {
        long step = stableCurrentStep();
        String userSecret = distinctSecret(step);
        createUser("resurrect-user", USER_PASS, userSecret, null);

        String sec1 = clientSecret("reused-v1");
        JsonNode v1 = createClient("reused-service-id", sec1, ALL_SCOPES);
        long id1 = v1.get("id").asLong();

        String activeOldToken = issueToken("reused-service-id", sec1, null);
        String revokedOldToken = issueToken("reused-service-id", sec1, null);

        int revStatus = revokeRaw(mockMvc, basicAuth("reused-service-id", sec1), revokedOldToken)
                .getResponse().getStatus();
        assertTrue(revStatus == 200 || revStatus == 204,
                "Expected 200/204 revoking token, got " + revStatus);
        assertRejected4xx(callOtpValidate(mockMvc, revokedOldToken, "resurrect-user",
                otpForStep(userSecret, step)).getResponse().getStatus(),
                "Revoked old token before client deletion");
        assertEquals(200, callOtpValidate(mockMvc, activeOldToken, "resurrect-user",
                otpForStep(userSecret, step - 1)).getResponse().getStatus());

        int delStatus = deleteClientRaw(mockMvc, id1).getResponse().getStatus();
        assertTrue(delStatus >= 200 && delStatus < 300,
                "Expected 2xx deleting client, got " + delStatus);
        assertRejected4xx(callOtpValidate(mockMvc, activeOldToken, "resurrect-user",
                otpForStep(userSecret, step)).getResponse().getStatus(),
                "Deleted client old token before clientId reuse");

        // Re-create client with the same clientId and a brand-new secret
        String sec2 = clientSecret("reused-v2");
        createClient("reused-service-id", sec2, ALL_SCOPES);

        for (String oldTok : List.of(activeOldToken, revokedOldToken)) {
            assertRejected4xx(callOtpValidate(mockMvc, oldTok, "resurrect-user",
                    otpForStep(userSecret, step)).getResponse().getStatus(),
                    "Old or revoked token from deleted client must never work after clientId reuse");
            assertRejected4xx(callAuthLogin(mockMvc, oldTok, "resurrect-user", USER_PASS,
                    otpForStep(userSecret, step)).getResponse().getStatus(),
                    "Old or revoked token from deleted client must never work on /v1/api/auth/login");
            assertRejected4xx(callMfaPreAuth(mockMvc, oldTok, "resurrect-user",
                    Integer.parseInt(otpForStep(userSecret, step))).getResponse().getStatus(),
                    "Old or revoked token from deleted client must never work on /v1/api/mfa/preauth");
            assertIntrospectInactiveOrForbidden(mockMvc, "reused-service-id", sec2, oldTok);
        }

        String freshToken = issueToken("reused-service-id", sec2, null);
        assertEquals(200, callOtpValidate(mockMvc, freshToken, "resurrect-user",
                otpForStep(userSecret, step)).getResponse().getStatus());
    }

    // 24
    @Test
    void concurrentDuplicateClientCreationRejectsLoserWith409Or400Never500() throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(2);
        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch start = new CountDownLatch(1);
        List<Throwable> errors = java.util.Collections.synchronizedList(new ArrayList<>());
        try {
            List<Future<Integer>> futures = new ArrayList<>();
            for (int i = 0; i < 2; i++) {
                final int idx = i;
                futures.add(pool.submit(() -> {
                    ready.countDown();
                    assertTrue(start.await(5, TimeUnit.SECONDS));
                    try {
                        return createClientRaw(mockMvc, clientPayload(
                                null, "conc-dup-client", clientSecret("conc-dup-" + idx),
                                "Conc Dup " + idx, true, false, null, List.of(SCOPE_OTP_VALIDATE)))
                                .getResponse().getStatus();
                    } catch (Throwable t) {
                        errors.add(t);
                        return -1;
                    }
                }));
            }
            assertTrue(ready.await(5, TimeUnit.SECONDS));
            start.countDown();
            List<Integer> statuses = new ArrayList<>();
            for (Future<Integer> f : futures) {
                statuses.add(f.get(10, TimeUnit.SECONDS));
            }
            assertTrue(errors.isEmpty(),
                    "Concurrent duplicate clientId creation must return 4xx, never throw unhandled exception: " + errors);
            long createdCount = statuses.stream().filter(s -> s >= 200 && s < 300).count();
            long conflictCount = statuses.stream().filter(s -> s >= 400 && s < 500 && s != 404 && s != 405).count();
            assertEquals(1L, createdCount,
                    "Expected exactly 1 concurrent creation to succeed, got statuses=" + statuses);
            assertEquals(1L, conflictCount,
                    "Expected duplicate concurrent creation to return 4xx (not 404/405), got statuses=" + statuses);
        } finally {
            pool.shutdownNow();
        }
    }

    // 25
    @Test
    @WithMockUser(roles = "ADMIN")
    void updatingClientMetadataDuringTemporaryLockoutDoesNotPermanentlyBlockClient() throws Exception {
        configurePolicy(2, 3, 300, AuthMode.PASSWORD_AND_OTP);
        String sec = clientSecret("cooldown-edit");
        JsonNode created = createClient(mockMvc, "cooldown-edit-client", sec, "Cooldown Client",
                true, false, AuthMode.PASSWORD_ONLY, List.of(SCOPE_OTP_VALIDATE));
        long id = created.get("id").asLong();

        requestTokenRaw(mockMvc, basicAuth("cooldown-edit-client", "Wrong1"), "client_credentials", null);
        requestTokenRaw(mockMvc, basicAuth("cooldown-edit-client", "Wrong2"), "client_credentials", null);
        assertRejected4xx(requestTokenRaw(mockMvc, basicAuth("cooldown-edit-client", sec),
                "client_credentials", null).getResponse().getStatus(),
                "Client should be temporarily locked out");

        MvcResult getRes = getClientRaw(mockMvc, id);
        assertEquals(200, getRes.getResponse().getStatus());
        JsonNode current = JSON.readTree(getRes.getResponse().getContentAsString());
        boolean currentEnabled = current.path("enabled").asBoolean(true);
        boolean currentBlocked = current.path("blocked").asBoolean(false);
        AuthMode currentAuthMode = current.hasNonNull("authMode")
                ? AuthMode.valueOf(current.get("authMode").asText())
                : null;
        List<String> currentScopes = new ArrayList<>();
        for (JsonNode s : current.path("scopes")) {
            currentScopes.add(s.asText());
        }

        updateClient(mockMvc, id, "cooldown-edit-client", null, "Renamed During Cooldown",
                currentEnabled, currentBlocked, currentAuthMode, currentScopes);

        Thread.sleep(3500L);

        String recoveredToken = issueToken("cooldown-edit-client", sec, null);
        assertFalse(recoveredToken.isBlank());
        MvcResult afterCooldown = getClientRaw(mockMvc, id);
        assertEquals(200, afterCooldown.getResponse().getStatus());
        assertFalse(JSON.readTree(afterCooldown.getResponse().getContentAsString()).path("blocked").asBoolean(),
                "Metadata update during temporary brute-force lockout must not permanently block client");
    }
}
