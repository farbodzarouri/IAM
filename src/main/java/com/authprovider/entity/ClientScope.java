package com.authprovider.entity;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

import java.util.Optional;

/**
 * OAuth 2.0 scopes (RFC 6749 section 3.3) that may be granted to machine-to-machine {@link OAuthClient}s.
 * Each scope authorizes calls to specific protected endpoints.
 */
public enum ClientScope {
    /** {@code POST /v1/api/auth/login}. */
    AUTH_LOGIN("auth:login"),
    /** {@code POST /v1/api/otp/validate} and {@code POST /v1/api/otp/validate-ocra}. */
    OTP_VALIDATE("otp:validate"),
    /** {@code POST /v1/api/mfa/preauth}. */
    MFA_PREAUTH("mfa:preauth");

    private final String value;

    ClientScope(String value) {
        this.value = value;
    }

    @JsonValue
    public String value() {
        return value;
    }

    /** Spring Security authority granted to bearer tokens carrying this scope. */
    public String authority() {
        return "SCOPE_" + value;
    }

    public static Optional<ClientScope> find(String value) {
        if (value != null) {
            for (ClientScope scope : values()) {
                if (scope.value.equals(value)) {
                    return Optional.of(scope);
                }
            }
        }
        return Optional.empty();
    }

    @JsonCreator
    public static ClientScope fromValue(String value) {
        return find(value).orElseThrow(() -> new IllegalArgumentException("Unknown scope: " + value));
    }
}
