package com.authprovider.oauth2;

/**
 * JWS algorithms (RFC 7518 section 3.1) accepted by this server. Only {@code RS256}
 * (RSASSA-PKCS1-v1_5 using SHA-256) is supported; {@code none} and symmetric algorithms are never
 * accepted, preventing algorithm substitution attacks.
 */
public enum JwsAlgorithm {
    RS256("SHA256withRSA");

    private final String jcaName;

    JwsAlgorithm(String jcaName) {
        this.jcaName = jcaName;
    }

    public String jcaName() {
        return jcaName;
    }
}
