package com.authprovider;

import com.authprovider.entity.AuthAuditLog;
import com.authprovider.entity.AuthMode;
import com.authprovider.entity.User;
import com.authprovider.oauth2.Base64Url;
import com.authprovider.oauth2.RsaJwk;
import com.authprovider.repository.AuthAuditLogRepository;
import com.authprovider.repository.OAuthClientRepository;
import com.authprovider.service.UserService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(properties = {
        "radius.enabled=false",
        "iam.oauth2.issuer=https://iam.test.example",
        "iam.oauth2.audience=https://iam.test.example/v1/api"
})
@AutoConfigureMockMvc
class OAuth2ClientCredentialsIntegrationTest {

    private static final String USER_PASS = "UserPass!123";

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private OAuthClientRepository clientRepository;
    @Autowired private AuthAuditLogRepository auditRepository;
    @Autowired private UserService userService;
    @Autowired private com.authprovider.TestClientAssignments assignments;

    private record Registered(long id, String clientId, String secret) {
    }

    // ---------------------------------------------------------------- helpers

    private static MockHttpServletRequestBuilder asAdmin(MockHttpServletRequestBuilder builder) {
        return builder.with(user("root").roles("ADMIN"));
    }

    private Registered register(String scopesJson) throws Exception {
        return register(scopesJson, null);
    }

    private Registered register(String scopesJson, AuthMode authMode) throws Exception {
        String clientId = "sys-" + UUID.randomUUID();
        String body = "{\"clientId\":\"" + clientId + "\",\"name\":\"Connected system\",\"scopes\":" + scopesJson
                + (authMode == null ? "" : ",\"authMode\":\"" + authMode + "\"") + "}";
        JsonNode json = json(mockMvc.perform(asAdmin(post("/v1/api/oauth-clients/create"))
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-store"))
                .andReturn());
        assertEquals(clientId, json.get("clientId").asText());
        assertTrue(json.get("enabled").asBoolean());
        assertFalse(json.get("blocked").asBoolean());
        String secret = json.get("clientSecret").asText();
        assertTrue(secret.length() >= 32, "generated secret must be high entropy");
        return new Registered(json.get("id").asLong(), clientId, secret);
    }

    private static String basic(String clientId, String secret) {
        String credentials = URLEncoder.encode(clientId, StandardCharsets.UTF_8) + ":"
                + URLEncoder.encode(secret, StandardCharsets.UTF_8);
        return "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
    }

    private ResultActions tokenRequest(String clientId, String secret, String form) throws Exception {
        MockHttpServletRequestBuilder request = post("/oauth2/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .content(form);
        if (clientId != null) {
            request.header(HttpHeaders.AUTHORIZATION, basic(clientId, secret));
        }
        return mockMvc.perform(request);
    }

    private String token(Registered client, String scope) throws Exception {
        assignments.assignAll();
        String form = "grant_type=client_credentials" + (scope == null ? "" : "&scope=" + URLEncoder.encode(scope,
                StandardCharsets.UTF_8));
        return json(tokenRequest(client.clientId(), client.secret(), form)
                .andExpect(status().isOk())
                .andReturn()).get("access_token").asText();
    }

    private ResultActions introspect(Registered caller, String token) throws Exception {
        return mockMvc.perform(post("/oauth2/introspect")
                .header(HttpHeaders.AUTHORIZATION, basic(caller.clientId(), caller.secret()))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .content("token=" + token + "&token_type_hint=access_token"));
    }

    private ResultActions revoke(Registered caller, String token) throws Exception {
        return mockMvc.perform(post("/oauth2/revoke")
                .header(HttpHeaders.AUTHORIZATION, basic(caller.clientId(), caller.secret()))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .content("token=" + token));
    }

    private ResultActions validateOtp(String bearer) throws Exception {
        MockHttpServletRequestBuilder request = post("/v1/api/otp/validate")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"nobody-" + UUID.randomUUID() + "\",\"otp\":\"123456\"}");
        if (bearer != null) {
            request.header(HttpHeaders.AUTHORIZATION, "Bearer " + bearer);
        }
        return mockMvc.perform(request);
    }

    private ResultActions updateClient(long id, String body) throws Exception {
        return mockMvc.perform(asAdmin(put("/v1/api/oauth-clients/" + id))
                .contentType(MediaType.APPLICATION_JSON).content(body));
    }

    private JsonNode json(MvcResult result) throws Exception {
        return objectMapper.readTree(result.getResponse().getContentAsString());
    }

    private static JsonNode decodePart(ObjectMapper mapper, String part) throws Exception {
        return mapper.readTree(Base64Url.decode(part));
    }

    // ---------------------------------------------------------------- client registry

    @Test
    void clientRegistryRequiresAdministratorAndNeverExposesSecretHash() throws Exception {
        mockMvc.perform(get("/v1/api/oauth-clients/all")).andExpect(status().isUnauthorized());
        mockMvc.perform(get("/v1/api/oauth-clients/all").with(user("operator").roles("USER")))
                .andExpect(status().isForbidden());

        Registered client = register("[\"otp:validate\"]");
        String bearer = token(client, null);
        mockMvc.perform(get("/v1/api/oauth-clients/all").header(HttpHeaders.AUTHORIZATION, "Bearer " + bearer))
                .andExpect(status().isUnauthorized());

        String listing = mockMvc.perform(asAdmin(get("/v1/api/oauth-clients/all")))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        assertTrue(listing.contains(client.clientId()));
        assertFalse(listing.contains(client.secret()));
        assertFalse(listing.contains("$2a$"));

        mockMvc.perform(asAdmin(get("/v1/api/oauth-clients/" + client.id())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.clientSecret").doesNotExist())
                .andExpect(jsonPath("$.scopes[0]").value("otp:validate"));

        String stored = clientRepository.findById(client.id()).orElseThrow().getClientSecretHash();
        assertTrue(stored.startsWith("$2"), "client secrets must be stored as BCrypt hashes");

        mockMvc.perform(asAdmin(post("/v1/api/oauth-clients/create")).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"clientId\":\"" + client.clientId() + "\",\"scopes\":[\"otp:validate\"]}"))
                .andExpect(status().isConflict());
        mockMvc.perform(asAdmin(post("/v1/api/oauth-clients/create")).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"clientId\":\"bad-scope-client\",\"scopes\":[\"admin:all\"]}"))
                .andExpect(status().isBadRequest());
        mockMvc.perform(asAdmin(post("/v1/api/oauth-clients/create")).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"clientId\":\"no-scope-client\"}"))
                .andExpect(status().isBadRequest());
        mockMvc.perform(asAdmin(get("/v1/api/oauth-clients/999999"))).andExpect(status().isNotFound());

        mockMvc.perform(asAdmin(delete("/v1/api/oauth-clients/" + client.id()))).andExpect(status().isOk());
        validateOtp(bearer).andExpect(status().isUnauthorized());
        tokenRequest(client.clientId(), client.secret(), "grant_type=client_credentials")
                .andExpect(status().isUnauthorized());
    }

    // ---------------------------------------------------------------- token endpoint (RFC 6749 / RFC 9068)

    @Test
    void clientCredentialsGrantIssuesVerifiableRs256AccessToken() throws Exception {
        Registered client = register("[\"otp:validate\",\"mfa:preauth\"]");

        MvcResult result = tokenRequest(client.clientId(), client.secret(), "grant_type=client_credentials")
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-store"))
                .andExpect(header().string(HttpHeaders.PRAGMA, "no-cache"))
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.expires_in").value(300))
                .andExpect(jsonPath("$.refresh_token").doesNotExist())
                // Omitted scope defaults to the client's registered scopes.
                .andExpect(jsonPath("$.scope").value("otp:validate mfa:preauth"))
                .andReturn();
        String accessToken = json(result).get("access_token").asText();

        String[] parts = accessToken.split("\\.");
        assertEquals(3, parts.length);
        JsonNode header = decodePart(objectMapper, parts[0]);
        JsonNode claims = decodePart(objectMapper, parts[1]);
        assertEquals("RS256", header.get("alg").asText());
        assertEquals("at+jwt", header.get("typ").asText());
        String kid = header.get("kid").asText();

        assertEquals("https://iam.test.example", claims.get("iss").asText());
        assertEquals("https://iam.test.example/v1/api", claims.get("aud").asText());
        assertEquals(client.clientId(), claims.get("sub").asText());
        assertEquals(client.clientId(), claims.get("client_id").asText());
        assertEquals("otp:validate mfa:preauth", claims.get("scope").asText());
        assertFalse(claims.get("jti").asText().isBlank());
        long now = Instant.now().getEpochSecond();
        assertTrue(Math.abs(claims.get("iat").asLong() - now) < 60);
        assertEquals(300, claims.get("exp").asLong() - claims.get("iat").asLong());

        JsonNode jwks = json(mockMvc.perform(get("/oauth2/jwks"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith("application/jwk-set+json"))
                .andReturn());
        JsonNode jwk = null;
        for (JsonNode key : jwks.get("keys")) {
            assertFalse(key.has("d"), "JWK Set must not expose private key members");
            if (kid.equals(key.get("kid").asText())) {
                jwk = key;
            }
        }
        assertNotNull(jwk, "signing key must be published in the JWK Set");
        assertEquals("RSA", jwk.get("kty").asText());
        assertEquals("sig", jwk.get("use").asText());
        assertEquals("RS256", jwk.get("alg").asText());
        RsaJwk parsed = RsaJwk.fromJson(jwk);
        assertEquals(kid, RsaJwk.thumbprint(parsed.publicKey()), "kid must be the RFC 7638 thumbprint");
        assertTrue(parsed.publicKey().getModulus().bitLength() >= 2048);

        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(parsed.publicKey());
        verifier.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
        assertTrue(verifier.verify(Base64Url.decode(parts[2])));

        tokenRequest(client.clientId(), client.secret(), "grant_type=client_credentials&scope=mfa:preauth")
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.scope").value("mfa:preauth"));
    }

    @Test
    void tokenEndpointRejectsInvalidRequestsWithRfc6749Errors() throws Exception {
        Registered client = register("[\"otp:validate\"]");

        tokenRequest(null, null, "grant_type=client_credentials")
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, startsWith("Basic")))
                .andExpect(jsonPath("$.error").value("invalid_client"));
        tokenRequest(client.clientId(), "wrong-secret-value", "grant_type=client_credentials")
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_client"));
        tokenRequest("unknown-client", "whatever-secret", "grant_type=client_credentials")
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_client"));
        mockMvc.perform(post("/oauth2/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .content("grant_type=client_credentials&client_id=" + client.clientId()
                                + "&client_secret=" + client.secret()))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_client"));

        tokenRequest(client.clientId(), client.secret(), "grant_type=password&username=a&password=b")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("unsupported_grant_type"));
        tokenRequest(client.clientId(), client.secret(), "scope=otp:validate")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_request"));
        tokenRequest(client.clientId(), client.secret(), "grant_type=client_credentials&scope=auth:login")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_scope"));
        tokenRequest(client.clientId(), client.secret(), "grant_type=client_credentials&scope=unknown")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_scope"));
        tokenRequest(client.clientId(), client.secret(),
                "grant_type=client_credentials&grant_type=client_credentials")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_request"));
        mockMvc.perform(post("/oauth2/token?grant_type=client_credentials")
                        .header(HttpHeaders.AUTHORIZATION, basic(client.clientId(), client.secret()))
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_request"));
        mockMvc.perform(post("/oauth2/token")
                        .header(HttpHeaders.AUTHORIZATION, basic(client.clientId(), client.secret()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"grant_type\":\"client_credentials\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_request"));
        mockMvc.perform(get("/oauth2/token")).andExpect(status().isMethodNotAllowed());

        List<AuthAuditLog> audit = auditRepository.findByChannelOrderByIdAsc(AuthAuditLog.Channel.OAUTH2_TOKEN);
        assertTrue(audit.stream().anyMatch(e -> client.clientId().equals(e.getUsername())
                && e.getOutcome() == AuthAuditLog.Outcome.FAILURE && "INVALID_SECRET".equals(e.getReason())));
    }

    // ---------------------------------------------------------------- bearer protection (RFC 6750)

    @Test
    void protectedEndpointsRequireBearerTokenWithMatchingScope() throws Exception {
        Registered otpClient = register("[\"otp:validate\"]");
        String bearer = token(otpClient, null);

        for (String path : List.of("/v1/api/auth/login", "/v1/api/otp/validate", "/v1/api/otp/validate-ocra",
                "/v1/api/mfa/preauth")) {
            mockMvc.perform(post(path).contentType(MediaType.APPLICATION_JSON).content("{}"))
                    .andExpect(status().isUnauthorized())
                    .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, startsWith("Bearer realm=")));
            mockMvc.perform(post(path).with(user("root").roles("ADMIN"))
                            .contentType(MediaType.APPLICATION_JSON).content("{}"))
                    .andExpect(status().isUnauthorized());
        }

        validateOtp(bearer)
                .andExpect(status().isUnauthorized())
                .andExpect(header().doesNotExist(HttpHeaders.WWW_AUTHENTICATE))
                .andExpect(jsonPath("$.status").value("INVALID_OTP"));
        mockMvc.perform(post("/v1/api/otp/validate-ocra").header(HttpHeaders.AUTHORIZATION, "Bearer " + bearer)
                        .contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(header().doesNotExist(HttpHeaders.WWW_AUTHENTICATE));

        mockMvc.perform(post("/v1/api/auth/login").header(HttpHeaders.AUTHORIZATION, "Bearer " + bearer)
                        .contentType(MediaType.APPLICATION_JSON).content("{\"username\":\"x\",\"password\":\"y\"}"))
                .andExpect(status().isForbidden())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("error=\"insufficient_scope\"")))
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("scope=\"auth:login\"")));
        mockMvc.perform(post("/v1/api/mfa/preauth").header(HttpHeaders.AUTHORIZATION, "Bearer " + bearer)
                        .contentType(MediaType.APPLICATION_JSON).content("{\"username\":\"x\",\"otp\":1}"))
                .andExpect(status().isForbidden());

        mockMvc.perform(post("/v1/api/otp/validate?access_token=" + bearer)
                        .contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isBadRequest())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("invalid_request")));

        validateOtp("not-a-jwt")
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("error=\"invalid_token\"")));

        // Tampered payload (scope escalation) and "alg":"none" tokens are rejected.
        String[] parts = bearer.split("\\.");
        JsonNode claims = decodePart(objectMapper, parts[1]);
        String escalated = objectMapper.writeValueAsString(((com.fasterxml.jackson.databind.node.ObjectNode) claims)
                .put("scope", "otp:validate auth:login"));
        String tampered = parts[0] + "." + Base64Url.encode(escalated.getBytes(StandardCharsets.UTF_8)) + "." + parts[2];
        mockMvc.perform(post("/v1/api/auth/login").header(HttpHeaders.AUTHORIZATION, "Bearer " + tampered)
                        .contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isUnauthorized());
        String none = Base64Url.encode("{\"alg\":\"none\",\"typ\":\"at+jwt\"}".getBytes(StandardCharsets.UTF_8))
                + "." + parts[1] + ".";
        validateOtp(none).andExpect(status().isUnauthorized());
        String hs256 = Base64Url.encode(("{\"alg\":\"HS256\",\"typ\":\"at+jwt\",\"kid\":\""
                + decodePart(objectMapper, parts[0]).get("kid").asText() + "\"}").getBytes(StandardCharsets.UTF_8))
                + "." + parts[1] + "." + parts[2];
        validateOtp(hs256).andExpect(status().isUnauthorized());

        assertTrue(auditRepository.findByChannelOrderByIdAsc(AuthAuditLog.Channel.OAUTH2_BEARER).stream()
                .anyMatch(e -> "INSUFFICIENT_SCOPE".equals(e.getReason())
                        && otpClient.clientId().equals(e.getUsername())));
        assertTrue(auditRepository.findByChannelOrderByIdAsc(AuthAuditLog.Channel.OTP_VALIDATION).stream()
                .anyMatch(e -> otpClient.clientId().equals(e.getClientName())),
                "audit records of protected endpoints must identify the calling client");
    }

    // ---------------------------------------------------------------- revocation & introspection

    @Test
    void revokedTokensAreRejectedAndIntrospectedInactive() throws Exception {
        Registered client = register("[\"otp:validate\"]");
        Registered other = register("[\"otp:validate\"]");
        String bearer = token(client, null);

        introspect(client, bearer)
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-store"))
                .andExpect(jsonPath("$.active").value(true))
                .andExpect(jsonPath("$.client_id").value(client.clientId()))
                .andExpect(jsonPath("$.scope").value("otp:validate"))
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.sub").value(client.clientId()))
                .andExpect(jsonPath("$.iss").value("https://iam.test.example"))
                .andExpect(jsonPath("$.exp").isNumber());
        introspect(other, bearer).andExpect(status().isOk()).andExpect(jsonPath("$.active").value(false));
        introspect(client, "garbage").andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value(false))
                .andExpect(jsonPath("$.client_id").doesNotExist());
        mockMvc.perform(post("/oauth2/introspect").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .content("token=" + bearer))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_client"));

        revoke(other, bearer).andExpect(status().isBadRequest());
        validateOtp(bearer).andExpect(header().doesNotExist(HttpHeaders.WWW_AUTHENTICATE));

        revoke(client, bearer).andExpect(status().isOk());
        revoke(client, bearer).andExpect(status().isOk());
        revoke(client, "garbage").andExpect(status().isOk());

        validateOtp(bearer)
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("error=\"invalid_token\"")));
        introspect(client, bearer).andExpect(jsonPath("$.active").value(false));

        String fresh = token(client, null);
        validateOtp(fresh).andExpect(header().doesNotExist(HttpHeaders.WWW_AUTHENTICATE));
        assertTrue(auditRepository.findByChannelOrderByIdAsc(AuthAuditLog.Channel.OAUTH2_REVOCATION).stream()
                .anyMatch(e -> "TOKEN_REVOKED".equals(e.getReason())));
    }

    // ---------------------------------------------------------------- client changes invalidate tokens

    @Test
    void secretRotationScopeChangesAndDisablingInvalidateIssuedTokens() throws Exception {
        Registered client = register("[\"otp:validate\",\"mfa:preauth\"]");
        String before = token(client, null);

        JsonNode rotated = json(updateClient(client.id(), "{\"clientSecret\":\"new-rotated-secret-value\"}")
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.clientSecret").value("new-rotated-secret-value"))
                .andReturn());
        assertNotNull(rotated.get("secretRotatedAt"));
        validateOtp(before).andExpect(status().isUnauthorized())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("invalid_token")));
        tokenRequest(client.clientId(), client.secret(), "grant_type=client_credentials")
                .andExpect(status().isUnauthorized());
        Registered current = new Registered(client.id(), client.clientId(), "new-rotated-secret-value");

        String afterRotation = token(current, null);
        validateOtp(afterRotation).andExpect(header().doesNotExist(HttpHeaders.WWW_AUTHENTICATE));

        // Partial update without security-relevant changes keeps tokens valid.
        updateClient(client.id(), "{\"name\":\"Renamed system\"}")
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("Renamed system"))
                .andExpect(jsonPath("$.enabled").value(true))
                .andExpect(jsonPath("$.clientSecret").doesNotExist());
        validateOtp(afterRotation).andExpect(header().doesNotExist(HttpHeaders.WWW_AUTHENTICATE));

        updateClient(client.id(), "{\"scopes\":[\"mfa:preauth\"]}").andExpect(status().isOk());
        validateOtp(afterRotation).andExpect(status().isUnauthorized());
        tokenRequest(current.clientId(), current.secret(), "grant_type=client_credentials&scope=otp:validate")
                .andExpect(jsonPath("$.error").value("invalid_scope"));

        updateClient(client.id(), "{\"scopes\":[\"otp:validate\"]}").andExpect(status().isOk());
        String beforeDisable = token(current, null);
        updateClient(client.id(), "{\"enabled\":false}").andExpect(status().isOk())
                .andExpect(jsonPath("$.enabled").value(false));
        validateOtp(beforeDisable).andExpect(status().isUnauthorized());
        tokenRequest(current.clientId(), current.secret(), "grant_type=client_credentials")
                .andExpect(status().isUnauthorized());
        updateClient(client.id(), "{\"enabled\":true}").andExpect(status().isOk());
        validateOtp(beforeDisable).andExpect(status().isUnauthorized());

        String beforeBlock = token(current, null);
        updateClient(client.id(), "{\"blocked\":true}").andExpect(status().isOk())
                .andExpect(jsonPath("$.blocked").value(true));
        validateOtp(beforeBlock).andExpect(status().isUnauthorized());
        tokenRequest(current.clientId(), current.secret(), "grant_type=client_credentials")
                .andExpect(status().isUnauthorized());
        updateClient(client.id(), "{\"blocked\":false}").andExpect(status().isOk())
                .andExpect(jsonPath("$.blocked").value(false));
        token(current, null);

        JsonNode generated = json(mockMvc.perform(asAdmin(post("/v1/api/oauth-clients/" + client.id() + "/rotate-secret")))
                .andExpect(status().isOk()).andReturn());
        String newSecret = generated.get("clientSecret").asText();
        tokenRequest(current.clientId(), current.secret(), "grant_type=client_credentials")
                .andExpect(status().isUnauthorized());
        token(new Registered(client.id(), client.clientId(), newSecret), null);

        assertTrue(auditRepository.findByChannelOrderByIdAsc(AuthAuditLog.Channel.OAUTH2_CLIENT_ADMIN).stream()
                .anyMatch(e -> "SECRET_ROTATED".equals(e.getReason()) && "root".equals(e.getUsername())
                        && client.clientId().equals(e.getClientName())));
    }

    // ---------------------------------------------------------------- brute force

    @Test
    void repeatedSecretFailuresLockClientUntilAdministratorUnblocks() throws Exception {
        Registered client = register("[\"otp:validate\"]");
        for (int i = 0; i < 5; i++) {
            tokenRequest(client.clientId(), "wrong-secret-" + i, "grant_type=client_credentials")
                    .andExpect(status().isUnauthorized());
        }
        // Locked out: even the correct secret is refused on every client-authenticated endpoint.
        tokenRequest(client.clientId(), client.secret(), "grant_type=client_credentials")
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_client"));
        introspect(client, "x").andExpect(status().isUnauthorized());

        mockMvc.perform(asAdmin(get("/v1/api/oauth-clients/" + client.id())))
                .andExpect(jsonPath("$.blocked").value(false))
                .andExpect(jsonPath("$.locked").value(true))
                .andExpect(jsonPath("$.lockedUntil").exists());
        assertTrue(auditRepository.findByChannelOrderByIdAsc(AuthAuditLog.Channel.OAUTH2_TOKEN).stream()
                .anyMatch(e -> client.clientId().equals(e.getUsername())
                        && e.getOutcome() == AuthAuditLog.Outcome.LOCKED));

        updateClient(client.id(), "{\"blocked\":false}")
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.blocked").value(false))
                .andExpect(jsonPath("$.locked").value(false))
                .andExpect(jsonPath("$.lockedUntil").doesNotExist());
        token(client, null);
    }

    // ---------------------------------------------------------------- per-client AuthMode override

    @Test
    void clientAuthModeOverrideAppliesToRestLogin() throws Exception {
        String username = "m2m-user-" + UUID.randomUUID().toString().substring(0, 8);
        User user = userService.saveUser(User.builder().username(username).password(USER_PASS)
                .otpToken(com.authprovider.TestUsers.token("JBSWY3DPEHPK3PXP")).build());
        assertNotNull(user.getId());
        String body = "{\"username\":\"" + username + "\",\"password\":\"" + USER_PASS + "\"}";

        Registered strict = register("[\"auth:login\"]");
        mockMvc.perform(post("/v1/api/auth/login").header(HttpHeaders.AUTHORIZATION, "Bearer " + token(strict, null))
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value("OTP_REQUIRED"));

        Registered passwordOnly = register("[\"auth:login\"]", AuthMode.PASSWORD_ONLY);
        mockMvc.perform(post("/v1/api/auth/login")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token(passwordOnly, null))
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("AUTHENTICATED"));
        assertTrue(auditRepository.findByUsernameOrderByIdAsc(username).stream()
                .anyMatch(e -> e.getChannel() == AuthAuditLog.Channel.WEB_LOGIN
                        && e.getOutcome() == AuthAuditLog.Outcome.SUCCESS
                        && passwordOnly.clientId().equals(e.getClientName())));

        // Removing the override (explicit null) restores the policy default.
        updateClient(passwordOnly.id(), "{\"authMode\":null}").andExpect(status().isOk())
                .andExpect(jsonPath("$.authMode").doesNotExist());
        mockMvc.perform(post("/v1/api/auth/login")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token(passwordOnly, null))
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(jsonPath("$.status").value("OTP_REQUIRED"));
    }
}
