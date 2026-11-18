package com.authprovider.dto;

import com.authprovider.entity.AuthMode;
import com.authprovider.entity.User;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserResponse {
    private Long id;
    private String username;
    private boolean enabled;
    private AuthMode authMode;
    private Long personId;
    private Long otpTokenId;

    public static UserResponse from(User user) {
        if (user == null) {
            return null;
        }
        return UserResponse.builder()
                .id(user.getId())
                .username(user.getUsername())
                .enabled(user.isEnabled())
                .authMode(user.getAuthMode())
                .personId(user.getPerson() == null ? null : user.getPerson().getId())
                .otpTokenId(user.getOtpToken() == null ? null : user.getOtpToken().getId())
                .build();
    }
}
