package com.authprovider.controller;

import com.authprovider.dto.OcraValidationRequest;
import com.authprovider.dto.OtpValidationRequest;
import com.authprovider.service.UserOtpService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/v1/api/otp")
@RequiredArgsConstructor(onConstructor_ = @Autowired)
public class OtpController {

    private final UserOtpService userOtpService;

    @PostMapping("/generate/{userId}")
    public ResponseEntity<String> generateSecret(@PathVariable Long userId) {
        return userOtpService.generateSecretForUser(userId)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @PostMapping("/validate")
    public ResponseEntity<Boolean> validateOtp(@RequestBody OtpValidationRequest request) {
        if (request == null) {
            return ResponseEntity.badRequest().body(false);
        }
        return userOtpService.validateUserOtp(request.getUserId(), request.getOtp())
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.badRequest().body(false));
    }

    @PostMapping("/validate-ocra")
    public ResponseEntity<Boolean> validateOcra(@RequestBody OcraValidationRequest request) {
        if (request == null) {
            return ResponseEntity.badRequest().body(false);
        }
        return userOtpService.validateUserOcra(request.getUserId(), request.getChallenge(), request.getOtp())
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.badRequest().body(false));
    }

    @ExceptionHandler({HttpMessageNotReadableException.class, MethodArgumentTypeMismatchException.class})
    public ResponseEntity<Boolean> handleInvalidPayload() {
        return ResponseEntity.badRequest().body(false);
    }
}



