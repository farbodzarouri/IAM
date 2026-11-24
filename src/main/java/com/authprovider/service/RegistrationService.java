package com.authprovider.service;

import com.authprovider.dto.UserRegistrationRequest;
import com.authprovider.dto.UserRegistrationResponse;

/**
 * Orchestrates atomic human-identity onboarding ({@link com.authprovider.entity.Person},
 * optional {@link com.authprovider.entity.OtpToken}, {@link com.authprovider.entity.User},
 * and initial client assignments).
 */
public interface RegistrationService {

    UserRegistrationResponse registerUser(UserRegistrationRequest request);
}
