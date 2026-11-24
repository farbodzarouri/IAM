package com.authprovider.dto;

import com.authprovider.entity.User;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserResponse {
    private Long id;
    private String username;
    private boolean enabled;
    private Long personId;
    private Long otpTokenId;
    /** Assignments to RADIUS clients. */
    private List<ClientAssignmentResponse> radiusClients;
    /** Assignments to OAuth 2.0 clients. */
    private List<ClientAssignmentResponse> oauthClients;

    public static UserResponse from(User user) {
        return from(user, List.of(), List.of());
    }

    public static UserResponse from(User user, List<ClientAssignmentResponse> radiusClients,
                                    List<ClientAssignmentResponse> oauthClients) {
        if (user == null) {
            return null;
        }
        return UserResponse.builder()
                .id(user.getId())
                .username(user.getUsername())
                .enabled(user.isEnabled())
                .personId(user.getPerson() == null ? null : user.getPerson().getId())
                .otpTokenId(user.getOtpToken() == null ? null : user.getOtpToken().getId())
                .radiusClients(radiusClients == null ? List.of() : radiusClients)
                .oauthClients(oauthClients == null ? List.of() : oauthClients)
                .build();
    }
}
