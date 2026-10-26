package com.authprovider.controller;

import com.authprovider.service.MfaPreAuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * Web form allowing (unauthenticated) RDG users to pre-authenticate their second factor.
 */
@Controller
@RequiredArgsConstructor
public class MfaWebController {

    private final MfaPreAuthService mfaPreAuthService;

    @GetMapping("/mfa")
    public String mfaForm() {
        return "mfa";
    }

    @PostMapping("/mfa")
    public String mfaSubmit(@RequestParam(value = "username", required = false) String username,
                            @RequestParam(value = "otp", required = false) String otp,
                            Model model) {
        Integer code = parseOtp(otp);
        boolean success = username != null && !username.isBlank() && code != null
                && mfaPreAuthService.preAuthenticate(username, code);
        model.addAttribute("success", success);
        model.addAttribute("username", username);
        model.addAttribute("message", success
                ? "MFA approved. You can now connect to the Remote Desktop Gateway."
                : "MFA verification failed. Please check your username and code and try again.");
        return "mfa";
    }

    private static Integer parseOtp(String otp) {
        if (otp == null) {
            return null;
        }
        String trimmed = otp.trim().replace(" ", "");
        if (trimmed.isEmpty() || trimmed.length() > 9 || !trimmed.chars().allMatch(Character::isDigit)) {
            return null;
        }
        return Integer.parseInt(trimmed);
    }
}
