package com.farbod.controller;

import com.farbod.entity.User;
import com.farbod.service.OtpService;
import com.farbod.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/otp")
public class OtpController {

    @Autowired
    private OtpService otpService;

    @Autowired
    private UserService userService;

    @PostMapping("/generate/{userId}")
    public ResponseEntity<String> generateSecret(@PathVariable Long userId) {
        User user = userService.getUserById(userId);
        if (user == null) {
            return ResponseEntity.notFound().build();
        }

        String secret = otpService.generateSecret();
        user.setSecret(secret);
        userService.saveUser(user);

        return ResponseEntity.ok(secret);
    }

    @PostMapping("/validate")
    public ResponseEntity<Boolean> validateOtp(@RequestBody Map<String, Object> payload) {
        Object userIdObj = payload.get("userId");
        Object otpObj = payload.get("otp");

        if (userIdObj == null || otpObj == null) {
             return ResponseEntity.badRequest().body(false);
        }

        Long userId = Long.valueOf(userIdObj.toString());
        Integer otp = Integer.valueOf(otpObj.toString());

        User user = userService.getUserById(userId);
        if (user == null || user.getSecret() == null) {
            return ResponseEntity.badRequest().body(false);
        }

        boolean isValid = otpService.validateOtp(user.getSecret(), otp);
        return ResponseEntity.ok(isValid);
    }

    @PostMapping("/validate-ocra")
    public ResponseEntity<Boolean> validateOcra(@RequestBody Map<String, Object> payload) {
        Object userIdObj = payload.get("userId");
        Object challengeObj = payload.get("challenge");
        Object otpObj = payload.get("otp");

        if (userIdObj == null || challengeObj == null || otpObj == null) {
             return ResponseEntity.badRequest().body(false);
        }

        Long userId = Long.valueOf(userIdObj.toString());
        String challenge = challengeObj.toString();
        String otp = otpObj.toString();

        User user = userService.getUserById(userId);
        if (user == null || user.getSecret() == null) {
            return ResponseEntity.badRequest().body(false);
        }

        boolean isValid = otpService.validateOcra(user.getSecret(), challenge, otp);
        return ResponseEntity.ok(isValid);
    }
}
