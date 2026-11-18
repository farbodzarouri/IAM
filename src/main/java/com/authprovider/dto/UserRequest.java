package com.authprovider.dto;

import com.authprovider.entity.AuthMode;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

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
    private AuthMode authMode;
}
