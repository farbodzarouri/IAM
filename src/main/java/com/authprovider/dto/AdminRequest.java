package com.authprovider.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AdminRequest {
    private String username;
    private String password;
    private String displayName;
    private Long personId;
    private Long otpTokenId;
    private Boolean enabled;
}
