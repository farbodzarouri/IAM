package com.authprovider.controller;

import com.authprovider.dto.MfaPreAuthRequest;
import com.authprovider.service.MfaPreAuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST endpoint used to pre-authenticate the second factor before launching an RDG session.
 */
@RestController
@RequestMapping("/v1/api/mfa")
@RequiredArgsConstructor
public class MfaController {

    private final MfaPreAuthService mfaPreAuthService;

    @PostMapping("/preauth")
    public ResponseEntity<Boolean> preAuthenticate(@RequestBody(required = false) MfaPreAuthRequest request) {
        if (request == null || request.getUsername() == null || request.getUsername().isBlank()
                || request.getOtp() == null) {
            return ResponseEntity.badRequest().body(false);
        }
        return ResponseEntity.ok(mfaPreAuthService.preAuthenticate(request.getUsername(), request.getOtp()));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<Boolean> handleInvalidPayload() {
        return ResponseEntity.badRequest().body(false);
    }
}
