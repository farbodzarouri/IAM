package com.authprovider.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

/**
 * Result of an atomic user registration workflow. {@code otpToken} includes provisioning
 * material ({@code secret}, {@code otpAuthUri}, {@code qrCode}) only when a brand-new
 * {@link com.authprovider.entity.OtpToken} was created during this registration.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserRegistrationResponse {

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class ProvisionedTokenInfo {
        private Long id;
        private Long personId;
        private String label;
        private boolean enabled;
        @ToString.Exclude
        private String secret;
        private String otpAuthUri;
        private String qrCode;
    }

    private PersonResponse person;
    private UserResponse user;
    private ProvisionedTokenInfo otpToken;
}
