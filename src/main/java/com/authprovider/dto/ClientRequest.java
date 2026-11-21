package com.authprovider.dto;

import com.authprovider.entity.AuthMode;
import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

import java.util.List;

/**
 * Create / update payload for registered OAuth 2.0 clients. On update, omitted ({@code null}) fields keep
 * their current value; an explicit {@code "authMode": null} removes the per-client override. A non-empty
 * {@code clientSecret} rotates the secret.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ClientRequest {
    private String clientId;
    @ToString.Exclude
    private String clientSecret;
    private String name;
    private Boolean enabled;
    private Boolean blocked;
    private AuthMode authMode;
    private List<String> scopes;

    @JsonIgnore
    @ToString.Exclude
    @Builder.Default
    private boolean authModePresent = false;

    public void setAuthMode(AuthMode authMode) {
        this.authMode = authMode;
        this.authModePresent = true;
    }

    /** Whether the payload specifies {@code authMode} (possibly {@code null} to clear the override). */
    @JsonIgnore
    public boolean isAuthModeSpecified() {
        return authModePresent || authMode != null;
    }
}
