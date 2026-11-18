package com.authprovider.controller;

import com.authprovider.dto.OcraValidationRequest;
import com.authprovider.dto.OtpGenerateRequest;
import com.authprovider.dto.OtpValidationRequest;
import com.authprovider.dto.OtpValidationResponse;
import com.authprovider.exception.BadRequestException;
import com.authprovider.service.UserOtpService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

@RestController
@RequestMapping("/v1/api/otp")
@RequiredArgsConstructor(onConstructor_ = @Autowired)
public class OtpController {

    private final UserOtpService userOtpService;

    @PostMapping("/generate")
    public ResponseEntity<String> generateSecret(@RequestBody(required = false) OtpGenerateRequest request) {
        if (request == null || request.getUsername() == null || request.getUsername().isBlank()) {
            throw new BadRequestException("Username is required");
        }
        return ResponseEntity.ok(userOtpService.generateSecretForUsername(request.getUsername()));
    }

    @PostMapping("/generate/{username:.+}")
    public ResponseEntity<String> generateSecretByPath(@PathVariable String username) {
        return ResponseEntity.ok(userOtpService.generateSecretForUsername(username));
    }

    @PostMapping(value = "/validate", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<OtpValidationResponse> validateOtp(@RequestBody(required = false) OtpValidationRequest request) {
        if (request == null) {
            return respond(OtpValidationResponse.invalidRequest("Username and 6-digit OTP are required"));
        }
        return respond(userOtpService.validateOtpByUsername(request.getUsername(), request.getOtp()));
    }

    @PostMapping(value = "/validate-ocra", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<OtpValidationResponse> validateOcra(@RequestBody(required = false) OcraValidationRequest request) {
        if (request == null) {
            return respond(OtpValidationResponse.invalidRequest("Username, challenge, and OTP are required"));
        }
        return respond(userOtpService.validateOcraByUsername(
                request.getUsername(), request.getChallenge(), request.getOtp()));
    }

    @ExceptionHandler({HttpMessageNotReadableException.class, MethodArgumentTypeMismatchException.class})
    public ResponseEntity<OtpValidationResponse> handleInvalidPayload() {
        return respond(OtpValidationResponse.invalidRequest("Malformed OTP validation request"));
    }

    private static ResponseEntity<OtpValidationResponse> respond(OtpValidationResponse response) {
        return ResponseEntity.status(response.getHttpStatus())
                .cacheControl(CacheControl.noStore())
                .header(HttpHeaders.PRAGMA, "no-cache")
                .contentType(MediaType.APPLICATION_JSON)
                .body(response);
    }
}
