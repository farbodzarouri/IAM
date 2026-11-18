package com.authprovider.dto;

import com.authprovider.entity.Admin;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AdminResponse {
    private Long id;
    private String username;
    private boolean enabled;
    private Long personId;
    private Long otpTokenId;
    private Instant createdAt;
    private Instant updatedAt;

    public static AdminResponse from(Admin admin) {
        if (admin == null) {
            return null;
        }
        return AdminResponse.builder()
                .id(admin.getId())
                .username(admin.getUsername())
                .enabled(admin.isEnabled())
                .personId(admin.getPerson() == null ? null : admin.getPerson().getId())
                .otpTokenId(admin.getOtpToken() == null ? null : admin.getOtpToken().getId())
                .createdAt(admin.getCreatedAt())
                .updatedAt(admin.getUpdatedAt())
                .build();
    }
}
