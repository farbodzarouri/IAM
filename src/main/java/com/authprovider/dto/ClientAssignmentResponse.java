package com.authprovider.dto;

import com.authprovider.entity.AuthMode;
import com.authprovider.entity.ClientType;
import com.authprovider.entity.UserOAuthClient;
import com.authprovider.entity.UserRadiusClient;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * A user's assignment to a RADIUS or OAuth 2.0 client ({@code clientId} is the client's database id).
 * Never contains client secrets.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ClientAssignmentResponse {
    private Long userId;
    private Long clientId;
    private ClientType type;
    private String clientName;
    private boolean enabled;
    private AuthMode authMode;

    public static ClientAssignmentResponse from(UserRadiusClient assignment) {
        if (assignment == null) {
            return null;
        }
        return ClientAssignmentResponse.builder()
                .userId(assignment.getUserId())
                .clientId(assignment.getClientId())
                .type(ClientType.RADIUS)
                .clientName(assignment.getClient() == null ? null : assignment.getClient().getName())
                .enabled(assignment.isEnabled())
                .authMode(assignment.getAuthMode())
                .build();
    }

    public static ClientAssignmentResponse from(UserOAuthClient assignment) {
        if (assignment == null) {
            return null;
        }
        return ClientAssignmentResponse.builder()
                .userId(assignment.getUserId())
                .clientId(assignment.getClientId())
                .type(ClientType.OAUTH2)
                .clientName(assignment.getClient() == null ? null : assignment.getClient().getName())
                .enabled(assignment.isEnabled())
                .authMode(assignment.getAuthMode())
                .build();
    }
}
