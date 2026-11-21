package com.authprovider.oauth2;

import com.authprovider.config.OAuth2Properties;
import com.authprovider.entity.OAuthSigningKey;
import com.authprovider.repository.OAuthSigningKeyRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Cluster-wide RSA signing key management for RS256 access tokens.
 * <ul>
 *     <li>Keys are persisted in {@code oauth_signing_keys}; every node loads them from the database and
 *     caches them for {@code iam.oauth2.key-cache-seconds} (an unknown {@code kid} triggers a rate-limited
 *     reload, so a key generated on another node is picked up immediately).</li>
 *     <li>Each key signs during {@code [signFrom, signUntil)}. The successor key is generated and published in
 *     the JWK Set ahead of its activation so that relying parties caching the JWK Set see it before use.</li>
 *     <li>Keys stay published until every token they signed has expired ({@code verifyUntil}) and are then
 *     purged.</li>
 * </ul>
 * Concurrent key generation on several nodes is harmless: all generated keys are published and the most
 * recently activated one is used for signing.
 */
@Slf4j
@Service
public class SigningKeyService {

    private static final String PLAIN_PREFIX = "pkcs8:";
    private static final String ENCRYPTED_PREFIX = "aesgcm:v1:";
    private static final int PBKDF2_ITERATIONS = 210_000;
    private static final int GCM_TAG_BITS = 128;
    private static final Duration MIN_FORCED_RELOAD_INTERVAL = Duration.ofSeconds(1);
    private static final Duration VERIFY_GRACE = Duration.ofSeconds(60);

    /** Public view of a signing key. */
    public record KeyInfo(Long id, String kid, RSAPublicKey publicKey, Instant signFrom, Instant signUntil,
                          Instant verifyUntil) {
    }

    /** Key material used for signing. */
    public record SigningKey(String kid, PrivateKey privateKey) {
        @Override
        public String toString() {
            return "SigningKey[kid=" + kid + "]";
        }
    }

    private record Snapshot(List<KeyInfo> keys, Instant loadedAt) {
    }

    private final OAuthSigningKeyRepository repository;
    private final OAuth2Properties properties;
    private final Clock clock;
    private final SecureRandom random;
    private final Map<String, PrivateKey> privateKeys = new ConcurrentHashMap<>();
    private final Object generationLock = new Object();
    private volatile Snapshot snapshot = new Snapshot(List.of(), Instant.EPOCH);
    private volatile Instant lastForcedReload = Instant.EPOCH;
    private volatile boolean plaintextWarningLogged;

    public SigningKeyService(OAuthSigningKeyRepository repository, OAuth2Properties properties, Clock clock,
                             SecureRandom random) {
        this.repository = repository;
        this.properties = properties;
        this.clock = clock;
        this.random = random;
    }

    /** Returns the key to sign new tokens with, generating (and publishing) keys when required. */
    public SigningKey signingKey() {
        Instant now = now();
        Optional<KeyInfo> active = activeKey(keys(now), now);
        if (active.isEmpty() || needsSuccessor(active.get(), keys(now), now)) {
            synchronized (generationLock) {
                List<KeyInfo> fresh = reload(now);
                active = activeKey(fresh, now);
                if (active.isEmpty()) {
                    generate(now);
                    active = activeKey(reload(now), now);
                } else if (needsSuccessor(active.get(), fresh, now)) {
                    generate(active.get().signUntil());
                    reload(now);
                }
            }
        }
        KeyInfo key = active.orElseThrow(() -> new IllegalStateException("No signing key available"));
        return new SigningKey(key.kid(), privateKey(key));
    }

    /** Public key for {@code kid} if it is currently valid for verification. */
    public Optional<RSAPublicKey> verificationKey(String kid) {
        if (kid == null) {
            return Optional.empty();
        }
        Instant now = now();
        Optional<KeyInfo> key = find(keys(now), kid, now);
        if (key.isEmpty() && now.isAfter(lastForcedReload.plus(MIN_FORCED_RELOAD_INTERVAL))) {
            lastForcedReload = now;
            key = find(reload(now), kid, now);
        }
        return key.map(KeyInfo::publicKey);
    }

    /** Keys to publish in the JWK Set (RFC 7517 section 5). */
    public List<RsaJwk> publishedKeys() {
        Instant now = now();
        if (activeKey(keys(now), now).isEmpty()) {
            signingKey();
        }
        return keys(now).stream()
                .filter(k -> k.verifyUntil().isAfter(now))
                .map(k -> new RsaJwk(k.kid(), k.publicKey()))
                .toList();
    }

    /** Forces generation of a new key that becomes active immediately (emergency rotation). */
    public KeyInfo rotateNow() {
        synchronized (generationLock) {
            Instant now = now();
            OAuthSigningKey created = generate(now);
            reload(now);
            return find(keys(now), created.getKid(), now).orElseThrow();
        }
    }

    /** Second precision: persisted instants must compare exactly regardless of database timestamp precision. */
    private Instant now() {
        return clock.instant().truncatedTo(ChronoUnit.SECONDS);
    }

    private List<KeyInfo> keys(Instant now) {
        Snapshot current = snapshot;
        if (current.loadedAt().plusSeconds(properties.getKeyCacheSeconds()).isAfter(now)
                && !current.loadedAt().isAfter(now)) {
            return current.keys();
        }
        return reload(now);
    }

    private synchronized List<KeyInfo> reload(Instant now) {
        try {
            repository.deleteExpired(now);
        } catch (RuntimeException e) {
            log.debug("Unable to purge expired signing keys: {}", e.toString());
        }
        List<KeyInfo> loaded = new ArrayList<>();
        for (OAuthSigningKey entity : repository.findByVerifyUntilAfterOrderBySignFromDescIdDesc(now)) {
            try {
                RSAPublicKey publicKey = (RSAPublicKey) KeyFactory.getInstance("RSA")
                        .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(entity.getPublicKey())));
                if (!RsaJwk.thumbprint(publicKey).equals(entity.getKid())) {
                    log.error("Signing key {} does not match its key id; ignored", entity.getKid());
                    continue;
                }
                loaded.add(new KeyInfo(entity.getId(), entity.getKid(), publicKey, entity.getSignFrom(),
                        entity.getSignUntil(), entity.getVerifyUntil()));
            } catch (GeneralSecurityException | IllegalArgumentException | ClassCastException e) {
                log.error("Unable to load signing key {}; ignored", entity.getKid(), e);
            }
        }
        loaded.sort(Comparator.comparing(KeyInfo::signFrom).thenComparing(KeyInfo::id).reversed());
        List<KeyInfo> result = List.copyOf(loaded);
        privateKeys.keySet().removeIf(kid -> result.stream().noneMatch(k -> k.kid().equals(kid)));
        snapshot = new Snapshot(result, now);
        return result;
    }

    private static Optional<KeyInfo> activeKey(List<KeyInfo> keys, Instant now) {
        return keys.stream()
                .filter(k -> !k.signFrom().isAfter(now) && k.signUntil().isAfter(now))
                .findFirst();
    }

    private static Optional<KeyInfo> find(List<KeyInfo> keys, String kid, Instant now) {
        return keys.stream().filter(k -> k.kid().equals(kid) && k.verifyUntil().isAfter(now)).findFirst();
    }

    private boolean needsSuccessor(KeyInfo active, List<KeyInfo> keys, Instant now) {
        Duration prePublish = prePublishWindow();
        if (active.signUntil().minus(prePublish).isAfter(now)) {
            return false;
        }
        return keys.stream().noneMatch(k -> !k.signFrom().isBefore(active.signUntil()));
    }

    private Duration prePublishWindow() {
        Duration rotation = Duration.ofSeconds(properties.getSigningKeyRotationSeconds());
        Duration tenth = rotation.dividedBy(10);
        Duration day = Duration.ofDays(1);
        return tenth.compareTo(day) < 0 ? tenth : day;
    }

    private OAuthSigningKey generate(Instant signFrom) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(new RSAKeyGenParameterSpec(properties.getSigningKeySize(), RSAKeyGenParameterSpec.F4),
                    random);
            KeyPair pair = generator.generateKeyPair();
            RSAPublicKey publicKey = (RSAPublicKey) pair.getPublic();
            String kid = RsaJwk.thumbprint(publicKey);
            Instant signUntil = signFrom.plusSeconds(properties.getSigningKeyRotationSeconds());
            Instant verifyUntil = signUntil
                    .plusSeconds(properties.getAccessTokenTtlSeconds())
                    .plusSeconds(properties.getClockSkewSeconds())
                    .plus(VERIFY_GRACE);
            OAuthSigningKey entity = OAuthSigningKey.builder()
                    .kid(kid)
                    .publicKey(Base64.getEncoder().encodeToString(publicKey.getEncoded()))
                    .privateKey(protect(kid, pair.getPrivate().getEncoded()))
                    .createdAt(now())
                    .signFrom(signFrom)
                    .signUntil(signUntil)
                    .verifyUntil(verifyUntil)
                    .build();
            OAuthSigningKey saved = repository.saveAndFlush(entity);
            privateKeys.put(kid, pair.getPrivate());
            log.info("Generated RS256 signing key {} ({} bits) active from {} until {}", kid,
                    properties.getSigningKeySize(), signFrom, signUntil);
            return saved;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Unable to generate RSA signing key", e);
        }
    }

    private PrivateKey privateKey(KeyInfo key) {
        return privateKeys.computeIfAbsent(key.kid(), kid -> {
            OAuthSigningKey entity = repository.findById(key.id())
                    .orElseThrow(() -> new IllegalStateException("Signing key " + kid + " no longer exists"));
            try {
                return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(unprotect(kid,
                        entity.getPrivateKey())));
            } catch (GeneralSecurityException e) {
                throw new IllegalStateException("Unable to load private signing key " + kid, e);
            }
        });
    }

    private String protect(String kid, byte[] pkcs8) throws GeneralSecurityException {
        String secret = properties.getKeyEncryptionSecret();
        if (secret == null || secret.isEmpty()) {
            if (!plaintextWarningLogged) {
                plaintextWarningLogged = true;
                log.warn("iam.oauth2.key-encryption-secret is not set; OAuth 2.0 signing keys are stored unencrypted");
            }
            return PLAIN_PREFIX + Base64.getEncoder().encodeToString(pkcs8);
        }
        byte[] salt = new byte[16];
        byte[] iv = new byte[12];
        random.nextBytes(salt);
        random.nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, deriveKey(secret, salt), new GCMParameterSpec(GCM_TAG_BITS, iv));
        cipher.updateAAD(kid.getBytes(StandardCharsets.UTF_8));
        byte[] ciphertext = cipher.doFinal(pkcs8);
        Base64.Encoder b64 = Base64.getEncoder();
        return ENCRYPTED_PREFIX + b64.encodeToString(salt) + ":" + b64.encodeToString(iv) + ":"
                + b64.encodeToString(ciphertext);
    }

    private byte[] unprotect(String kid, String stored) throws GeneralSecurityException {
        if (stored.startsWith(PLAIN_PREFIX)) {
            return Base64.getDecoder().decode(stored.substring(PLAIN_PREFIX.length()));
        }
        if (!stored.startsWith(ENCRYPTED_PREFIX)) {
            throw new GeneralSecurityException("Unknown private key format");
        }
        String secret = properties.getKeyEncryptionSecret();
        if (secret == null || secret.isEmpty()) {
            throw new GeneralSecurityException("Signing key is encrypted but iam.oauth2.key-encryption-secret is not set");
        }
        String[] parts = stored.substring(ENCRYPTED_PREFIX.length()).split(":");
        if (parts.length != 3) {
            throw new GeneralSecurityException("Malformed encrypted private key");
        }
        Base64.Decoder b64 = Base64.getDecoder();
        byte[] salt = b64.decode(parts[0]);
        byte[] iv = b64.decode(parts[1]);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, deriveKey(secret, salt), new GCMParameterSpec(GCM_TAG_BITS, iv));
        cipher.updateAAD(kid.getBytes(StandardCharsets.UTF_8));
        return cipher.doFinal(b64.decode(parts[2]));
    }

    private static SecretKeySpec deriveKey(String secret, byte[] salt) throws GeneralSecurityException {
        char[] chars = secret.toCharArray();
        PBEKeySpec spec = new PBEKeySpec(chars, salt, PBKDF2_ITERATIONS, 256);
        try {
            byte[] key = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
            return new SecretKeySpec(key, "AES");
        } finally {
            spec.clearPassword();
            Arrays.fill(chars, '\0');
        }
    }
}
