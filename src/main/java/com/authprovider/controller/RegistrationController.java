package com.authprovider.controller;

import com.authprovider.dto.UserRegistrationRequest;
import com.authprovider.dto.UserRegistrationResponse;
import com.authprovider.service.RegistrationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Admin-only unified registration endpoint atomically creating/linking a {@link com.authprovider.entity.Person},
 * optional {@link com.authprovider.entity.OtpToken}, {@link com.authprovider.entity.User}, and initial client
 * access bindings.
 */
@RestController
@RequestMapping("/v1/api/registration")
@RequiredArgsConstructor
public class RegistrationController {

    private final RegistrationService registrationService;

    @PostMapping({"", "/users"})
    public ResponseEntity<UserRegistrationResponse> registerUser(
            @RequestBody(required = false) UserRegistrationRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .cacheControl(CacheControl.noStore())
                .header(HttpHeaders.PRAGMA, "no-cache")
                .body(registrationService.registerUser(request));
    }
}
