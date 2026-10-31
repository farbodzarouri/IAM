package com.authprovider.controller;

import com.authprovider.dto.LoginRequest;
import com.authprovider.dto.LoginResponse;
import com.authprovider.service.LoginService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/v1/api/auth")
@RequiredArgsConstructor(onConstructor_ = @Autowired)
public class AuthController {

    private final LoginService loginService;

    @PostMapping(value = "/login", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<LoginResponse> login(@RequestBody(required = false) LoginRequest request) {
        return respond(loginService.login(request));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<LoginResponse> handleInvalidPayload() {
        return respond(LoginResponse.builder()
                .status(LoginResponse.Status.INVALID_REQUEST)
                .authenticated(false)
                .message("Malformed login request")
                .build());
    }

    private static ResponseEntity<LoginResponse> respond(LoginResponse response) {
        return ResponseEntity.status(response.getHttpStatus())
                .cacheControl(CacheControl.noStore())
                .header(HttpHeaders.PRAGMA, "no-cache")
                .contentType(MediaType.APPLICATION_JSON)
                .body(response);
    }
}
