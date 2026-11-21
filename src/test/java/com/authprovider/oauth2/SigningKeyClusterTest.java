package com.authprovider.oauth2;

import com.authprovider.MutableClock;
import com.authprovider.config.OAuth2Properties;
import com.authprovider.entity.ClientScope;
import com.authprovider.entity.OAuthClient;
import com.authprovider.entity.OAuthSigningKey;
import com.authprovider.repository.OAuthClientRepository;
import com.authprovider.repository.OAuthRevokedTokenRepository;
import com.authprovider.repository.OAuthSigningKeyRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Simulates several cluster nodes sharing one database: signing keys, key rotation, encrypted key storage,
 * token expiry and revocation must behave consistently across nodes.
 */
@DataJpaTest
class SigningKeyClusterTest {

    @Autowired private OAuthSigningKeyRepository keyRepository;
    @Autowired private OAuthRevokedTokenRepository revokedRepository;
    @Autowired private OAuthClientRepository clientRepository;

    private final SecureRandom random = new SecureRandom();
    private MutableClock clock;
    private OAuth2Properties properties;
    private OAuthClient client;

    @BeforeEach
    void setUp() {
        clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
        properties = new OAuth2Properties();
        properties.setSigningKeyRotationSeconds(Duration.ofDays(10).toSeconds());
        properties.setKeyEncryptionSecret("cluster-shared-key-encryption-secret");
        properties.validate();
        client = clientRepository.saveAndFlush(OAuthClient.builder()
                .clientId("cluster-client")
                .name("cluster-client")
                .clientSecretHash("$2a$10$abcdefghijklmnopqrstuuJQ8a0bqv6p0R3w1Nq3U5jF8m1e2b3c4")
                .scopes(EnumSet.of(ClientScope.OTP_VALIDATE))
                .tokenVersion("v1")
                .build());
    }

    private SigningKeyService keyNode() {
        return new SigningKeyService(keyRepository, properties, clock, random);
    }

    private AccessTokenService tokenNode(SigningKeyService keys) {
        return new AccessTokenService(keys, new TokenRevocationStore(revokedRepository, clock), clientRepository,
                properties, clock, random);
    }

    @Test
    void nodesShareSigningKeysAndVerifyEachOthersTokens() {
        SigningKeyService keysA = keyNode();
        SigningKeyService keysB = keyNode();
        AccessTokenService nodeA = tokenNode(keysA);
        AccessTokenService nodeB = tokenNode(keysB);

        String token = nodeA.issue(client, Set.of(ClientScope.OTP_VALIDATE)).value();
        assertTrue(nodeB.validate(token).isValid(), "a token issued on one node must be accepted by every node");
        assertEquals(keysA.signingKey().kid(), keysB.signingKey().kid());
        assertEquals(1, keyRepository.count());

        OAuthSigningKey stored = keyRepository.findAll().get(0);
        assertTrue(stored.getPrivateKey().startsWith("aesgcm:v1:"), "private keys must be encrypted at rest");
    }

    @Test
    void encryptedKeysCannotBeUsedWithAWrongSecret() {
        keyNode().signingKey();
        OAuth2Properties wrong = new OAuth2Properties();
        wrong.setSigningKeyRotationSeconds(properties.getSigningKeyRotationSeconds());
        wrong.setKeyEncryptionSecret("another-secret");
        SigningKeyService node = new SigningKeyService(keyRepository, wrong, clock, random);
        assertThrows(IllegalStateException.class, node::signingKey);
    }

    @Test
    void keysRotateWithPrePublicationAndRetireAfterTheirTokensExpire() {
        SigningKeyService keys = keyNode();
        AccessTokenService tokens = tokenNode(keys);
        String firstKid = keys.signingKey().kid();
        String oldToken = tokens.issue(client, Set.of(ClientScope.OTP_VALIDATE)).value();

        // Within the pre-publication window the successor is published but not yet used.
        clock.advance(Duration.ofDays(10).minusHours(12));
        assertEquals(firstKid, keys.signingKey().kid());
        List<RsaJwk> published = keys.publishedKeys();
        assertEquals(2, published.size(), "successor key must be published before it signs tokens");

        clock.advance(Duration.ofHours(12));
        String secondKid = keys.signingKey().kid();
        assertNotEquals(firstKid, secondKid);
        assertTrue(keys.verificationKey(firstKid).isPresent(), "retired key stays valid until its tokens expire");
        assertFalse(tokens.validate(oldToken).isValid(), "expired tokens are rejected");
        assertEquals("TOKEN_EXPIRED", tokens.validate(oldToken).reason());

        clock.advance(Duration.ofSeconds(properties.getAccessTokenTtlSeconds() + properties.getClockSkewSeconds() + 61));
        assertTrue(keys.verificationKey(firstKid).isEmpty());
        assertTrue(keys.publishedKeys().stream().noneMatch(k -> k.kid().equals(firstKid)));
    }

    @Test
    void expiryRevocationAndClientVersionAreEnforced() {
        AccessTokenService tokens = tokenNode(keyNode());
        AccessTokenService otherNode = tokenNode(keyNode());
        AccessTokenService.IssuedToken issued = tokens.issue(client, Set.of(ClientScope.OTP_VALIDATE));

        clock.advance(Duration.ofSeconds(properties.getAccessTokenTtlSeconds() - 1));
        assertTrue(tokens.validate(issued.value()).isValid());
        clock.advance(Duration.ofSeconds(1 + properties.getClockSkewSeconds()));
        assertEquals("TOKEN_EXPIRED", tokens.validate(issued.value()).reason());

        AccessTokenService.IssuedToken second = tokens.issue(client, Set.of(ClientScope.OTP_VALIDATE));
        new TokenRevocationStore(revokedRepository, clock)
                .revoke(second.claims().jti(), client.getClientId(), second.claims().expiresAt());
        assertEquals("TOKEN_REVOKED", otherNode.validate(second.value()).reason(),
                "revocation must take effect on every node");

        AccessTokenService.IssuedToken third = tokens.issue(client, Set.of(ClientScope.OTP_VALIDATE));
        client.setTokenVersion("v2");
        clientRepository.saveAndFlush(client);
        assertEquals("CLIENT_CHANGED", otherNode.validate(third.value()).reason());

        OAuth2Properties otherIssuer = new OAuth2Properties();
        otherIssuer.setIssuer("urn:other");
        otherIssuer.setKeyEncryptionSecret(properties.getKeyEncryptionSecret());
        AccessTokenService foreign = new AccessTokenService(keyNode(), new TokenRevocationStore(revokedRepository, clock),
                clientRepository, otherIssuer, clock, random);
        assertEquals("INVALID_ISSUER", foreign.validate(tokens.issue(client, Set.of(ClientScope.OTP_VALIDATE)).value())
                .reason());
    }
}
