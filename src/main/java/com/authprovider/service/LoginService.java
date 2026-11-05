package com.authprovider.service;

import com.authprovider.dto.LoginRequest;
import com.authprovider.dto.LoginResponse;

public interface LoginService {
    LoginResponse login(LoginRequest request);
}
