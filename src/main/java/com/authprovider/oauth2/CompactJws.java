package com.authprovider.oauth2;

import com.fasterxml.jackson.databind.JsonNode;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * RS256 JWS Compact Serialization (RFC 7515 sections 3.1, 5.1, 5.2 and 7.1).
 */
public final class CompactJws {

    /** Upper bound on accepted compact JWS sizes (denial-of-service protection). */
    public static final int MAX_LENGTH = 8192;

    private final JsonNode header;
    private final byte[] payload;
    private final byte[] signingInput;
    private final byte[] signature;

    private CompactJws(JsonNode header, byte[] payload, byte[] signingInput, byte[] signature) {
        this.header = header;
        this.payload = payload;
        this.signingInput = signingInput;
        this.signature = signature;
    }

    /**
     * Creates a signed compact JWS. {@code alg} and {@code kid} are always set from the arguments.
     */
    public static String sign(Map<String, Object> protectedHeader, byte[] payload, String kid, PrivateKey key) {
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", JwsAlgorithm.RS256.name());
        header.putAll(protectedHeader);
        header.put("alg", JwsAlgorithm.RS256.name());
        header.put("kid", kid);
        String input = Base64Url.encode(JoseJson.serialize(header)) + "." + Base64Url.encode(payload);
        try {
            Signature signer = Signature.getInstance(JwsAlgorithm.RS256.jcaName());
            signer.initSign(key);
            signer.update(input.getBytes(StandardCharsets.US_ASCII));
            return input + "." + Base64Url.encode(signer.sign());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Unable to sign JWS", e);
        }
    }

    /**
     * Parses (but does not verify) a compact JWS. Only the RS256 algorithm, a {@code kid} header and no
     * {@code crit} extensions are accepted.
     *
     * @throws InvalidJwsException if the serialization or the protected header is invalid
     */
    public static CompactJws parse(String compact) {
        if (compact == null || compact.isEmpty() || compact.length() > MAX_LENGTH) {
            throw new InvalidJwsException("Token is missing or too large");
        }
        int first = compact.indexOf('.');
        int second = first < 0 ? -1 : compact.indexOf('.', first + 1);
        if (first <= 0 || second < 0 || compact.indexOf('.', second + 1) >= 0 || second == compact.length() - 1) {
            throw new InvalidJwsException("Token is not a compact JWS");
        }
        String encodedHeader = compact.substring(0, first);
        String encodedPayload = compact.substring(first + 1, second);
        String encodedSignature = compact.substring(second + 1);
        JsonNode header;
        byte[] payload;
        byte[] signature;
        try {
            header = JoseJson.parseObject(Base64Url.decode(encodedHeader));
            payload = Base64Url.decode(encodedPayload);
            signature = Base64Url.decode(encodedSignature);
        } catch (IllegalArgumentException e) {
            throw new InvalidJwsException("Malformed JWS encoding");
        }
        JsonNode alg = header.get("alg");
        if (alg == null || !alg.isTextual() || !JwsAlgorithm.RS256.name().equals(alg.asText())) {
            throw new InvalidJwsException("Unsupported JWS algorithm");
        }
        if (header.has("crit")) {
            // RFC 7515 section 4.1.11: no extensions are understood by this implementation.
            throw new InvalidJwsException("Unsupported critical header parameters");
        }
        if (header.has("jku") || header.has("jwk") || header.has("x5u") || header.has("x5c")) {
            // Keys are only ever taken from this server's own key store, never from the token.
            throw new InvalidJwsException("Embedded or referenced keys are not accepted");
        }
        JsonNode kid = header.get("kid");
        if (kid == null || !kid.isTextual() || kid.asText().isEmpty()) {
            throw new InvalidJwsException("Missing key id");
        }
        byte[] signingInput = compact.substring(0, second).getBytes(StandardCharsets.US_ASCII);
        return new CompactJws(header, payload, signingInput, signature);
    }

    /** Verifies the signature with the key resolved from the {@code kid} header. */
    public boolean verify(Function<String, RSAPublicKey> keyResolver) {
        RSAPublicKey key = keyResolver.apply(keyId());
        if (key == null) {
            return false;
        }
        int modulusBytes = (key.getModulus().bitLength() + 7) / 8;
        if (signature.length != modulusBytes) {
            return false;
        }
        try {
            Signature verifier = Signature.getInstance(JwsAlgorithm.RS256.jcaName());
            verifier.initVerify(key);
            verifier.update(signingInput);
            return verifier.verify(signature);
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    public String keyId() {
        return header.get("kid").asText();
    }

    /** The {@code typ} header value or {@code null}. */
    public String type() {
        JsonNode typ = header.get("typ");
        return typ != null && typ.isTextual() ? typ.asText() : null;
    }

    public JsonNode header() {
        return header;
    }

    public byte[] payload() {
        return payload.clone();
    }
}
