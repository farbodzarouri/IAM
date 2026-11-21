package com.authprovider.oauth2;

import com.authprovider.entity.ClientScope;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class JoseProtocolTest {

    private static final KeyPair KEYS = generate();
    private static final KeyPair OTHER_KEYS = generate();

    private static KeyPair generate() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String sign(String payload) {
        return CompactJws.sign(Map.of("typ", "at+jwt"), payload.getBytes(StandardCharsets.UTF_8), "k1",
                KEYS.getPrivate());
    }

    @Test
    void base64UrlIsStrictAndUnpadded() {
        assertEquals("AQID", Base64Url.encode(new byte[]{1, 2, 3}));
        assertEquals("_-8", Base64Url.encode(new byte[]{(byte) 0xff, (byte) 0xef}));
        assertArrayEquals(new byte[]{(byte) 0xff, (byte) 0xef}, Base64Url.decode("_-8"));
        assertThrows(IllegalArgumentException.class, () -> Base64Url.decode("AQ=="));
        assertThrows(IllegalArgumentException.class, () -> Base64Url.decode("A+/B"));
        assertThrows(IllegalArgumentException.class, () -> Base64Url.decode("A"));
        // Non-canonical trailing bits must not decode to the same bytes as the canonical form.
        assertThrows(IllegalArgumentException.class, () -> Base64Url.decode("AR"));
        assertEquals("AQAB", Base64Url.encodeUnsigned(BigInteger.valueOf(65537)));
        assertEquals(BigInteger.valueOf(65537), Base64Url.decodeUnsigned("AQAB"));
    }

    @Test
    void rfc7515AppendixA2HeaderEncoding() {
        // RFC 7515 Appendix A.2.1 example JWS Protected Header {"alg":"RS256"}.
        assertEquals("eyJhbGciOiJSUzI1NiJ9", Base64Url.encode("{\"alg\":\"RS256\"}".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void rfc7638ThumbprintMatchesSpecificationExample() throws Exception {
        // RFC 7638 section 3.1 example key and thumbprint.
        String n = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";
        RSAPublicKey key = (RSAPublicKey) java.security.KeyFactory.getInstance("RSA").generatePublic(
                new java.security.spec.RSAPublicKeySpec(Base64Url.decodeUnsigned(n), Base64Url.decodeUnsigned("AQAB")));
        assertEquals("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", RsaJwk.thumbprint(key));
        RsaJwk jwk = RsaJwk.of(key);
        assertEquals(n, jwk.toJson().get("n"));
        assertEquals("AQAB", jwk.toJson().get("e"));
        assertFalse(jwk.toJson().containsKey("d"));
    }

    @Test
    void signAndVerifyCompactJws() {
        String jws = sign("{\"sub\":\"a\"}");
        CompactJws parsed = CompactJws.parse(jws);
        assertEquals("k1", parsed.keyId());
        assertEquals("at+jwt", parsed.type());
        assertEquals("RS256", parsed.header().get("alg").asText());
        assertTrue(parsed.verify(kid -> "k1".equals(kid) ? (RSAPublicKey) KEYS.getPublic() : null));
        assertFalse(parsed.verify(kid -> (RSAPublicKey) OTHER_KEYS.getPublic()));
        assertFalse(parsed.verify(kid -> null));
    }

    @Test
    void parseRejectsUnsafeOrMalformedSerializations() {
        String jws = sign("{\"sub\":\"a\"}");
        String[] parts = jws.split("\\.");
        assertThrows(InvalidJwsException.class, () -> CompactJws.parse(parts[0] + "." + parts[1]));
        assertThrows(InvalidJwsException.class, () -> CompactJws.parse(jws + ".x"));
        assertThrows(InvalidJwsException.class, () -> CompactJws.parse(parts[0] + "." + parts[1] + "."));
        assertThrows(InvalidJwsException.class, () -> CompactJws.parse(parts[0] + "=." + parts[1] + "." + parts[2]));
        assertThrows(InvalidJwsException.class, () -> CompactJws.parse("x".repeat(CompactJws.MAX_LENGTH + 1)));
        for (String header : new String[]{
                "{\"alg\":\"none\",\"kid\":\"k1\"}",
                "{\"alg\":\"HS256\",\"kid\":\"k1\"}",
                "{\"alg\":\"rs256\",\"kid\":\"k1\"}",
                "{\"alg\":\"RS256\"}",
                "{\"alg\":\"RS256\",\"kid\":\"k1\",\"crit\":[\"exp\"]}",
                "{\"alg\":\"RS256\",\"kid\":\"k1\",\"jwk\":{}}",
                "{\"alg\":\"RS256\",\"kid\":\"k1\",\"jku\":\"https://evil\"}",
                "{\"alg\":\"RS256\",\"alg\":\"none\",\"kid\":\"k1\"}",
                "[\"alg\"]"}) {
            String forged = Base64Url.encode(header.getBytes(StandardCharsets.UTF_8)) + "." + parts[1] + "." + parts[2];
            assertThrows(InvalidJwsException.class, () -> CompactJws.parse(forged), header);
        }
    }

    @Test
    void duplicateClaimsAreRejected() {
        assertThrows(IllegalArgumentException.class,
                () -> JoseJson.parseObject("{\"scope\":\"a\",\"scope\":\"b\"}".getBytes(StandardCharsets.UTF_8)));
        assertThrows(IllegalArgumentException.class,
                () -> JoseJson.parseObject("{\"a\":1} {\"b\":2}".getBytes(StandardCharsets.UTF_8)));
        assertThrows(IllegalArgumentException.class,
                () -> JoseJson.parseObject(new byte[]{'{', '"', (byte) 0xC3, '"', ':', '1', '}'}));
    }

    @Test
    void scopeSyntaxFollowsRfc6749() {
        assertEquals(Set.of(ClientScope.AUTH_LOGIN, ClientScope.OTP_VALIDATE), Scopes.parse("otp:validate auth:login"));
        assertEquals("auth:login otp:validate mfa:preauth",
                Scopes.format(Set.of(ClientScope.MFA_PREAUTH, ClientScope.AUTH_LOGIN, ClientScope.OTP_VALIDATE)));
        assertThrows(IllegalArgumentException.class, () -> Scopes.parse(""));
        assertThrows(IllegalArgumentException.class, () -> Scopes.parse("auth:login  otp:validate"));
        assertThrows(IllegalArgumentException.class, () -> Scopes.parse(" auth:login"));
        assertThrows(IllegalArgumentException.class, () -> Scopes.parse("auth:login\totp:validate"));
        assertThrows(IllegalArgumentException.class, () -> Scopes.parse("openid"));
    }

    @Test
    void basicCredentialsAreFormDecoded() {
        String header = "Basic " + java.util.Base64.getEncoder().encodeToString(
                "my%20client:p%40ss%3Aword+x".getBytes(StandardCharsets.UTF_8));
        Optional<String[]> parsed = ClientAuthenticator.parseBasic(header);
        assertTrue(parsed.isPresent());
        assertEquals("my client", parsed.get()[0]);
        assertEquals("p@ss:word x", parsed.get()[1]);
        assertTrue(ClientAuthenticator.parseBasic("bAsIc " + java.util.Base64.getEncoder()
                .encodeToString("a:b".getBytes(StandardCharsets.UTF_8))).isPresent());
        assertTrue(ClientAuthenticator.parseBasic("Bearer abc").isEmpty());
        assertTrue(ClientAuthenticator.parseBasic("Basic !!!").isEmpty());
        assertTrue(ClientAuthenticator.parseBasic("Basic " + java.util.Base64.getEncoder()
                .encodeToString("no-colon".getBytes(StandardCharsets.UTF_8))).isEmpty());
        assertTrue(ClientAuthenticator.parseBasic("Basic " + java.util.Base64.getEncoder()
                .encodeToString("bad%zz:secret".getBytes(StandardCharsets.UTF_8))).isEmpty());
    }
}
