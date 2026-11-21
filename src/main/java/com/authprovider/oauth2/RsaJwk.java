package com.authprovider.oauth2;

import com.fasterxml.jackson.databind.JsonNode;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Public RSA signing key represented as a JSON Web Key (RFC 7517, RFC 7518 section 6.3.1). The key id is
 * the RFC 7638 SHA-256 JWK thumbprint, making it stable and identical on every cluster node.
 */
public record RsaJwk(String kid, RSAPublicKey publicKey) {

    public static final String KTY = "RSA";
    public static final String USE_SIG = "sig";

    public static RsaJwk of(RSAPublicKey publicKey) {
        return new RsaJwk(thumbprint(publicKey), publicKey);
    }

    /** RFC 7638 thumbprint: SHA-256 over the lexicographically ordered required members, no whitespace. */
    public static String thumbprint(RSAPublicKey key) {
        String canonical = "{\"e\":\"" + Base64Url.encodeUnsigned(key.getPublicExponent())
                + "\",\"kty\":\"RSA\",\"n\":\"" + Base64Url.encodeUnsigned(key.getModulus()) + "\"}";
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(canonical.getBytes(StandardCharsets.UTF_8));
            return Base64Url.encode(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /** JWK members published in the JWK Set (public parameters only). */
    public Map<String, Object> toJson() {
        Map<String, Object> jwk = new LinkedHashMap<>();
        jwk.put("kty", KTY);
        jwk.put("use", USE_SIG);
        jwk.put("alg", JwsAlgorithm.RS256.name());
        jwk.put("kid", kid);
        jwk.put("n", Base64Url.encodeUnsigned(publicKey.getModulus()));
        jwk.put("e", Base64Url.encodeUnsigned(publicKey.getPublicExponent()));
        return jwk;
    }

    /** Parses a public RSA JWK; private members are rejected. */
    public static RsaJwk fromJson(JsonNode node) {
        if (node == null || !node.isObject() || !KTY.equals(text(node, "kty"))) {
            throw new IllegalArgumentException("RSA JWK expected");
        }
        if (node.has("d") || node.has("p") || node.has("q")) {
            throw new IllegalArgumentException("Private key members are not permitted");
        }
        BigInteger n = Base64Url.decodeUnsigned(text(node, "n"));
        BigInteger e = Base64Url.decodeUnsigned(text(node, "e"));
        try {
            RSAPublicKey key = (RSAPublicKey) KeyFactory.getInstance("RSA")
                    .generatePublic(new RSAPublicKeySpec(n, e));
            String kid = text(node, "kid");
            return new RsaJwk(kid == null ? thumbprint(key) : kid, key);
        } catch (GeneralSecurityException ex) {
            throw new IllegalArgumentException("Invalid RSA key", ex);
        }
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value != null && value.isTextual() ? value.asText() : null;
    }

    @Override
    public String toString() {
        return "RsaJwk[kid=" + kid + ", bits=" + publicKey.getModulus().bitLength() + "]";
    }
}
