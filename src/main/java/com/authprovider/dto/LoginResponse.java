package com.authprovider.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class LoginResponse {

    public enum Status {
        AUTHENTICATED(200),
        ENROLLMENT_REQUIRED(200),
        INVALID_REQUEST(400),
        INVALID_CREDENTIALS(401),
        OTP_REQUIRED(401),
        INVALID_OTP(401),
        NOT_PROVISIONED(403),
        ACCOUNT_CONFLICT(409),
        ENROLLMENT_FAILED(500),
        DIRECTORY_UNAVAILABLE(503);

        private final int httpStatus;

        Status(int httpStatus) {
            this.httpStatus = httpStatus;
        }

        public int getHttpStatus() {
            return httpStatus;
        }
    }

    private Status status;
    private boolean authenticated;
    private String message;
    private Long userId;
    private String username;
    private String authenticationSource;
    @ToString.Exclude
    private String secret;
    @ToString.Exclude
    private String otpAuthUri;
    @ToString.Exclude
    private String qrCode;
    private String issuer;

    @JsonIgnore
    public int getHttpStatus() {
        return status == null ? 500 : status.getHttpStatus();
    }
}
