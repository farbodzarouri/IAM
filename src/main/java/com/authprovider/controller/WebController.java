package com.authprovider.controller;

import com.authprovider.entity.User;
import com.authprovider.service.OtpService;
import com.authprovider.service.QrCodeService;
import com.authprovider.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@RequiredArgsConstructor
@Controller
public class WebController {


    private final UserService userService;


    private final OtpService otpService;


    private final QrCodeService qrCodeService;

    @GetMapping("/")
    public String home() {
        return "redirect:/users";
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

    @org.springframework.web.bind.annotation.PostMapping("/users/add")
    public String addUser(@org.springframework.web.bind.annotation.ModelAttribute User user) {
        userService.saveUser(user);
        return "redirect:/users";
    }

    @GetMapping("/users/edit/{id}")
    public String editUserForm(@PathVariable("id") Long id, Model model) {
        User user = userService.getUserById(id);
        if (user == null) {
            return "redirect:/users";
        }
        model.addAttribute("user", user);
        return "edit";
    }

    @org.springframework.web.bind.annotation.PostMapping("/users/edit/{id}")
    public String editUserSubmit(@PathVariable("id") Long id, @org.springframework.web.bind.annotation.ModelAttribute User user) {
        user.setId(id);
        userService.saveUser(user);
        return "redirect:/users";
    }

    @org.springframework.web.bind.annotation.PostMapping("/users/delete/{id}")
    public String deleteUser(@PathVariable("id") Long id) {
        userService.deleteUser(id);
        return "redirect:/users";
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
