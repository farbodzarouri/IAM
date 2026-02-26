package com.farbod.controller;

import com.farbod.entity.User;
import com.farbod.service.OtpService;
import com.farbod.service.QrCodeService;
import com.farbod.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@Controller
public class WebController {

    @Autowired
    private UserService userService;

    @Autowired
    private OtpService otpService;

    @Autowired
    private QrCodeService qrCodeService;

    @GetMapping("/")
    public String home() {
        return "home";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/users")
    public String users(Model model) {
        model.addAttribute("users", userService.getAllUsers());
        return "users";
    }

    @GetMapping("/users/{id}/otp")
    public String otp(@PathVariable("id") Long id, Model model) {
        User user = userService.getUserById(id);
        model.addAttribute("user", user);
        if (user != null && user.getSecret() != null) {
            String otpAuthUrl = "otpauth://totp/IAM:" + user.getUsername() + "?secret=" + user.getSecret() + "&issuer=IAM";
            try {
                String qrCodeImage = qrCodeService.generateQrCodeImage(otpAuthUrl, 200, 200);
                model.addAttribute("qrCode", qrCodeImage);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return "otp";
    }

    @org.springframework.web.bind.annotation.PostMapping("/users/{id}/otp/generate")
    public String generateOtpWeb(@PathVariable("id") Long id) {
        User user = userService.getUserById(id);
        if (user != null) {
            String secret = otpService.generateSecret();
            user.setSecret(secret);
            userService.saveUser(user);
        }
        return "redirect:/users/" + id + "/otp";
    }
}
