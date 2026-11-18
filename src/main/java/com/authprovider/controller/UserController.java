package com.authprovider.controller;

import com.authprovider.dto.UserRequest;
import com.authprovider.dto.UserResponse;
import com.authprovider.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RequiredArgsConstructor
@RestController
@RequestMapping("/v1/api/users")
public class UserController {

    private final UserService userService;

    @GetMapping("/all")
    public List<UserResponse> getAllUsers() {
        return userService.getAllUsers().stream()
                .map(UserResponse::from)
                .toList();
    }

    @GetMapping("/{id}")
    public UserResponse getUserById(@PathVariable Long id) {
        return UserResponse.from(userService.getUserOrThrow(id));
    }

    @PostMapping("/create")
    public UserResponse createUser(@RequestBody UserRequest request) {
        return UserResponse.from(userService.createUser(request));
    }

    @PutMapping("/{id}")
    public UserResponse updateUser(@PathVariable Long id, @RequestBody UserRequest request) {
        return UserResponse.from(userService.updateUser(id, request));
    }

    @DeleteMapping("/{id}")
    public void deleteUser(@PathVariable Long id) {
        userService.deleteUser(id);
    }
}
