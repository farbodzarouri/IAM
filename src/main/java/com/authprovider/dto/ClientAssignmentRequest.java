package com.authprovider.dto;

import com.authprovider.entity.AuthMode;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Assignment of a user to a RADIUS or OAuth 2.0 client. {@code clientId} is the client's database id
 * ({@code client.id}); it is taken from the path for the {@code /v1/api/users/{userId}/...-clients/{clientId}}
 * endpoints and required in the {@code radiusClients} / {@code oauthClients} lists of a user payload.
 * {@code enabled} defaults to {@code true}; {@code authMode} is optional ({@code null} inherits the client mode).
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ClientAssignmentRequest {
    private Long clientId;
    private Boolean enabled;
    private AuthMode authMode;
}
