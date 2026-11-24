package com.authprovider.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * User account payload. {@code secret} (optional) is stored in the account's {@link com.authprovider.entity.OtpToken}.
 * {@code radiusClients} / {@code oauthClients} (optional) replace the user's client assignments when present;
 * {@code null} leaves them unchanged.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserRequest {
    private String username;
    private String password;
    private String secret;
    private Long personId;
    private Long otpTokenId;
    private Boolean enabled;
    private List<ClientAssignmentRequest> radiusClients;
    private List<ClientAssignmentRequest> oauthClients;
}
