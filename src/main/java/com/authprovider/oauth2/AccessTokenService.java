package com.authprovider.oauth2;

import com.authprovider.config.OAuth2Properties;
import com.authprovider.entity.ClientScope;
import com.authprovider.entity.OAuthClient;
import com.authprovider.repository.OAuthClientRepository;
import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Issues and validates RS256-signed JWT access tokens following the JWT Profile for OAuth 2.0 Access Tokens
 * (RFC 9068) for the {@code client_credentials} grant: header {@code typ=at+jwt}; claims {@code iss},
 * {@code sub} (= {@code client_id}), {@code aud}, {@code exp}, {@code iat}, {@code nbf}, {@code jti},
 * {@code client_id}, {@code scope}, plus the private claim {@value #CLAIM_VERSION} binding the token to the
 * client's current credential/permission version.
 * <p>
 * Validation is performed against shared database state on every call, so revocations (RFC 7009) and client
 * changes (secret rotation, scope reduction, disabling, blocking or deletion) take effect immediately on every
 * cluster node.
 */
@Service
public class AccessTokenService {

    public static final String TOKEN_TYPE = "at+jwt";
    static final String CLAIM_VERSION = "ver";

    /** Validated access token. */
    public record AccessToken(String jti, String issuer, String subject, String clientId, List<String> audience,
                              Set<ClientScope> scopes, Instant issuedAt, Instant notBefore, Instant expiresAt,
                              String version) {
    }

    /** Issued token and its metadata. */
    public record IssuedToken(String value, AccessToken claims) {
        @Override
        public String toString() {
            return "IssuedToken[jti=" + claims.jti() + "]";
        }
    }

    /** Outcome of token validation; {@code reason} is a machine-readable cause for audit records. */
    public record Validation(AccessToken token, OAuthClient client, String reason) {
        public boolean isValid() {
            return token != null && client != null && reason == null;
        }

        static Validation invalid(String reason) {
            return new Validation(null, null, reason);
        }

        static Validation invalid(AccessToken token, String reason) {
            return new Validation(token, null, reason);
        }
    }

    private final SigningKeyService keyService;
    private final TokenRevocationStore revocationStore;
    private final OAuthClientRepository clientRepository;
    private final OAuth2Properties properties;
    private final Clock clock;
    private final SecureRandom random;

    public AccessTokenService(SigningKeyService keyService, TokenRevocationStore revocationStore,
                              OAuthClientRepository clientRepository, OAuth2Properties properties, Clock clock,
                              SecureRandom random) {
        this.keyService = keyService;
        this.revocationStore = revocationStore;
        this.clientRepository = clientRepository;
        this.properties = properties;
        this.clock = clock;
        this.random = random;
    }

    public long accessTokenTtlSeconds() {
        return properties.getAccessTokenTtlSeconds();
    }

    public IssuedToken issue(OAuthClient client, Set<ClientScope> scopes) {
        Instant now = Instant.ofEpochSecond(clock.instant().getEpochSecond());
        Instant exp = now.plusSeconds(properties.getAccessTokenTtlSeconds());
        byte[] id = new byte[16];
        random.nextBytes(id);
        String jti = Base64Url.encode(id);

        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", properties.getIssuer());
        claims.put("sub", client.getClientId());
        claims.put("aud", properties.getAudience());
        claims.put("exp", exp.getEpochSecond());
        claims.put("nbf", now.getEpochSecond());
        claims.put("iat", now.getEpochSecond());
        claims.put("jti", jti);
        claims.put("client_id", client.getClientId());
        claims.put("scope", Scopes.format(scopes));
        claims.put(CLAIM_VERSION, client.getTokenVersion());

        SigningKeyService.SigningKey key = keyService.signingKey();
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("typ", TOKEN_TYPE);
        String value = CompactJws.sign(header, JoseJson.serialize(claims), key.kid(), key.privateKey());
        return new IssuedToken(value, new AccessToken(jti, properties.getIssuer(), client.getClientId(),
                client.getClientId(), List.of(properties.getAudience()), Set.copyOf(scopes), now, now, exp,
                client.getTokenVersion()));
    }

    /**
     * Full validation: signature, RFC 9068 header and claims, revocation status, and the current state of the
     * client the token was issued to.
     */
    public Validation validate(String token) {
        Validation verified = verify(token);
        if (verified.reason() != null) {
            return verified;
        }
        AccessToken claims = verified.token();
        if (revocationStore.isRevoked(claims.jti())) {
            return Validation.invalid(claims, "TOKEN_REVOKED");
        }
        Optional<OAuthClient> client = clientRepository.findByClientId(claims.clientId());
        if (client.isEmpty()) {
            return Validation.invalid(claims, "CLIENT_NOT_FOUND");
        }
        OAuthClient current = client.get();
        if (!current.isEnabled()) {
            return Validation.invalid(claims, "CLIENT_DISABLED");
        }
        if (current.isBlocked()) {
            return Validation.invalid(claims, "CLIENT_BLOCKED");
        }
        if (current.getTokenVersion() == null || !current.getTokenVersion().equals(claims.version())) {
            return Validation.invalid(claims, "CLIENT_CHANGED");
        }
        if (!current.getScopes().containsAll(claims.scopes())) {
            return Validation.invalid(claims, "SCOPE_WITHDRAWN");
        }
        return new Validation(claims, current, null);
    }

    /**
     * Verifies signature, header and claims only (no revocation or client state checks). The returned
     * validation carries the token claims when the token is authentic and unexpired.
     */
    public Validation verify(String token) {
        CompactJws jws;
        try {
            jws = CompactJws.parse(token);
        } catch (InvalidJwsException e) {
            return Validation.invalid("MALFORMED_TOKEN");
        }
        String typ = jws.type();
        if (typ == null || !isAccessTokenType(typ)) {
            return Validation.invalid("INVALID_TOKEN_TYPE");
        }
        if (!jws.verify(kid -> keyService.verificationKey(kid).orElse(null))) {
            return Validation.invalid("INVALID_SIGNATURE");
        }
        AccessToken claims;
        try {
            claims = parseClaims(JoseJson.parseObject(jws.payload()));
        } catch (IllegalArgumentException e) {
            return Validation.invalid("INVALID_CLAIMS");
        }
        Instant now = clock.instant();
        long skew = properties.getClockSkewSeconds();
        if (!now.isBefore(claims.expiresAt().plusSeconds(skew))) {
            return Validation.invalid(claims, "TOKEN_EXPIRED");
        }
        if (claims.issuedAt().isAfter(now.plusSeconds(skew))
                || (claims.notBefore() != null && claims.notBefore().isAfter(now.plusSeconds(skew)))) {
            return Validation.invalid(claims, "TOKEN_NOT_YET_VALID");
        }
        if (!properties.getIssuer().equals(claims.issuer())) {
            return Validation.invalid(claims, "INVALID_ISSUER");
        }
        if (!claims.audience().contains(properties.getAudience())) {
            return Validation.invalid(claims, "INVALID_AUDIENCE");
        }
        if (!claims.subject().equals(claims.clientId())) {
            return Validation.invalid(claims, "INVALID_SUBJECT");
        }
        return new Validation(claims, null, null);
    }

    private static boolean isAccessTokenType(String typ) {
        String normalized = typ.toLowerCase(Locale.ROOT);
        return normalized.equals(TOKEN_TYPE) || normalized.equals("application/" + TOKEN_TYPE);
    }

    private static AccessToken parseClaims(JsonNode claims) {
        String iss = requiredString(claims, "iss");
        String sub = requiredString(claims, "sub");
        String clientId = requiredString(claims, "client_id");
        String jti = requiredString(claims, "jti");
        String version = requiredString(claims, CLAIM_VERSION);
        String scope = requiredString(claims, "scope");
        Instant exp = requiredTime(claims, "exp");
        Instant iat = requiredTime(claims, "iat");
        Instant nbf = claims.has("nbf") ? requiredTime(claims, "nbf") : null;
        List<String> audience = new ArrayList<>();
        JsonNode aud = claims.get("aud");
        if (aud != null && aud.isTextual()) {
            audience.add(aud.asText());
        } else if (aud != null && aud.isArray()) {
            for (JsonNode entry : aud) {
                if (!entry.isTextual()) {
                    throw new IllegalArgumentException("Invalid aud");
                }
                audience.add(entry.asText());
            }
        } else {
            throw new IllegalArgumentException("Missing aud");
        }
        Set<ClientScope> scopes = Scopes.parse(scope);
        return new AccessToken(jti, iss, sub, clientId, List.copyOf(audience), scopes, iat, nbf, exp, version);
    }

    private static String requiredString(JsonNode claims, String name) {
        JsonNode node = claims.get(name);
        if (node == null || !node.isTextual() || node.asText().isEmpty()) {
            throw new IllegalArgumentException("Missing or invalid claim " + name);
        }
        return node.asText();
    }

    private static Instant requiredTime(JsonNode claims, String name) {
        JsonNode node = claims.get(name);
        if (node == null || !node.isNumber()) {
            throw new IllegalArgumentException("Missing or invalid claim " + name);
        }
        double seconds = node.asDouble();
        if (!Double.isFinite(seconds) || seconds < 0 || seconds > 253_402_300_799d) {
            throw new IllegalArgumentException("Out-of-range claim " + name);
        }
        return Instant.ofEpochSecond((long) Math.floor(seconds));
    }
}
