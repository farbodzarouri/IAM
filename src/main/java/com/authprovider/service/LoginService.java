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

    /**
     * Authenticates on behalf of the registered OAuth 2.0 client with database id {@code oauthClientId}. The
     * account must hold an enabled assignment to that client; the assignment's optional {@link AuthMode}
     * overrides {@code clientAuthMode}, which overrides the security policy default. Accounts auto-provisioned
     * from the directory during this login are assigned to (only) this client.
     */
    default LoginResponse login(LoginRequest request, Long oauthClientId, AuthMode clientAuthMode) {
        return login(request, clientAuthMode);
    }
}
