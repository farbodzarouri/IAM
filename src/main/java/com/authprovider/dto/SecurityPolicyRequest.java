package com.authprovider.dto;

import com.authprovider.entity.AuthMode;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SecurityPolicyRequest {

    private int maxFailures;
    private long lockoutSeconds;
    private long failureWindowSeconds;
    private long challengeTtlSeconds;
    private int challengeMaxPending;
    private long mfaApprovalTtlSeconds;
    private int mfaMaxFailedAttempts;
    private long mfaLockoutWindowSeconds;
    private long otpReuseWindowSeconds;
    private boolean requireMessageAuthenticator;

    @Builder.Default
    private boolean stripRealm = true;

    @Builder.Default
    private String challengePrompt = "Enter your one-time passcode";

    @Builder.Default
    private boolean mfaOutOfBandEnabled = true;

    @Builder.Default
    private AuthMode defaultAuthMode = AuthMode.PASSWORD_AND_OTP;
}
