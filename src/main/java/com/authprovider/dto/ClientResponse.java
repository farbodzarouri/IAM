package com.authprovider.dto;

import com.authprovider.entity.AuthMode;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

import java.time.Instant;
import java.util.List;

/**
 * Registered OAuth 2.0 client. {@code clientSecret} is only returned in plain text when it is created or
 * rotated (it is stored as a BCrypt hash and cannot be retrieved later). {@code blocked} reflects persistent
 * administrative blocking, while {@code locked} and {@code lockedUntil} reflect temporary brute-force
 * lockout after repeated authentication failures.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ClientResponse {
    private Long id;
    private String clientId;
    @ToString.Exclude
    private String clientSecret;
    private String name;
    private boolean enabled;
    private boolean blocked;
    private boolean locked;
    private Instant lockedUntil;
    private AuthMode authMode;
    private List<String> scopes;
    private Instant secretRotatedAt;
    private Instant createdAt;
    private Instant updatedAt;
}
