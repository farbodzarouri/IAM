package com.authprovider.service;

import com.authprovider.dto.LoginRequest;
import com.authprovider.dto.LoginResponse;
import com.authprovider.entity.AuthMode;

public interface LoginService {
    LoginResponse login(LoginRequest request);

    /**
     * Authenticates on behalf of a connected system whose registered OAuth 2.0 client carries an optional
     * {@link AuthMode} override ({@code null} inherits the security policy default).
     */
    default LoginResponse login(LoginRequest request, AuthMode clientAuthMode) {
        return login(request);
    }
}
