package com.authprovider.controller;

import com.authprovider.dto.UserRequest;
import com.authprovider.entity.User;
import com.authprovider.service.OtpProvisioningSupport;
import com.authprovider.service.QrCodeGenerator;
import com.authprovider.service.UserOtpService;
import com.authprovider.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;

@Slf4j
@RequiredArgsConstructor
@Controller
public class WebController {

    private final UserService userService;
    private final UserOtpService userOtpService;
    private final QrCodeGenerator qrCodeGenerator;

    @GetMapping("/")
    public String home() {
        return "redirect:/users";
    }

    @GetMapping("/users")
    public String users(Model model) {
        model.addAttribute("users", userService.getAllUsers());
        return "users";
    }

    @PostMapping("/users/add")
    public String addUser(@ModelAttribute UserRequest request) {
        userService.createUser(request);
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

    @PostMapping("/users/edit/{id}")
    public String editUserSubmit(@PathVariable("id") Long id, @ModelAttribute UserRequest request) {
        userService.updateUser(id, request);
        return "redirect:/users";
    }

    @PostMapping("/users/delete/{id}")
    public String deleteUser(@PathVariable("id") Long id) {
        userService.deleteUser(id);
        return "redirect:/users";
    }

    @GetMapping("/users/{id}/otp")
    public String otp(@PathVariable("id") Long id, Model model) {
        User user = userService.getUserById(id);
        model.addAttribute("user", user);
        if (user != null && user.getSecret() != null) {
            try {
                OtpProvisioningSupport.ProvisioningQr qr = OtpProvisioningSupport.generate(
                        qrCodeGenerator, user.getUsername(), user.getSecret());
                model.addAttribute("qrCode", qr.qrCode());
            } catch (Exception e) {
                log.error("Failed to generate QR code for user {}", id, e);
            }
        }
        return "otp";
    }

    @PostMapping("/users/{id}/otp/generate")
    public String generateOtpWeb(@PathVariable("id") Long id) {
        userOtpService.generateSecretForUser(id);
        return "redirect:/users/" + id + "/otp";
    }
}
