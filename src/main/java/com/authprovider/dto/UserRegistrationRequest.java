package com.authprovider.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

import java.util.List;

/**
 * Atomic onboarding payload that creates or links a {@link com.authprovider.entity.Person},
 * an optional {@link com.authprovider.entity.OtpToken}, a {@link com.authprovider.entity.User},
 * and initial RADIUS / OAuth 2.0 client assignments inside one transaction.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserRegistrationRequest {

    public record OtpTokenSpec(String label, @ToString.Exclude String secret, Boolean enabled) {
    }

    private String username;
    @ToString.Exclude
    private String password;
    private Boolean enabled;
    private Long personId;
    private PersonRequest person;
    private Long otpTokenId;
    private OtpTokenSpec otpToken;
    private Boolean provisionOtpToken;
    private List<ClientAssignmentRequest> radiusClients;
    private List<ClientAssignmentRequest> oauthClients;
}
