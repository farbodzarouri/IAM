package com.authprovider.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.http.HttpStatus;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class OtpValidationResponse {

    public enum Status {
        VALID(HttpStatus.OK),
        INVALID_OTP(HttpStatus.UNAUTHORIZED),
        LOCKED(HttpStatus.FORBIDDEN),
        NOT_ENROLLED(HttpStatus.FORBIDDEN),
        INVALID_REQUEST(HttpStatus.BAD_REQUEST);

        private final HttpStatus httpStatus;

        Status(HttpStatus httpStatus) {
            this.httpStatus = httpStatus;
        }

        public HttpStatus httpStatus() {
            return httpStatus;
        }
    }

    private boolean valid;
    private Status status;
    private String username;
    private String message;

    @JsonIgnore
    public HttpStatus getHttpStatus() {
        return status == null ? HttpStatus.BAD_REQUEST : status.httpStatus();
    }

    public static OtpValidationResponse valid(String username) {
        return OtpValidationResponse.builder()
                .valid(true)
                .status(Status.VALID)
                .username(username)
                .message("OTP verified")
                .build();
    }

    public static OtpValidationResponse invalidOtp(String username) {
        return OtpValidationResponse.builder()
                .valid(false)
                .status(Status.INVALID_OTP)
                .username(username)
                .message("Invalid one-time password")
                .build();
    }

    public static OtpValidationResponse locked(String username) {
        return OtpValidationResponse.builder()
                .valid(false)
                .status(Status.LOCKED)
                .username(username)
                .message("Account is locked or disabled")
                .build();
    }

    public static OtpValidationResponse notEnrolled(String username) {
        return OtpValidationResponse.builder()
                .valid(false)
                .status(Status.NOT_ENROLLED)
                .username(username)
                .message("OTP token is not enrolled")
                .build();
    }

    public static OtpValidationResponse invalidRequest(String message) {
        return OtpValidationResponse.builder()
                .valid(false)
                .status(Status.INVALID_REQUEST)
                .message(message)
                .build();
    }
}
