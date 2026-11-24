package com.authprovider.controller;

import com.authprovider.dto.ClientAssignmentRequest;
import com.authprovider.dto.ClientAssignmentResponse;
import com.authprovider.dto.UserRegistrationRequest;
import com.authprovider.dto.UserRegistrationResponse;
import com.authprovider.dto.UserRequest;
import com.authprovider.dto.UserResponse;
import com.authprovider.entity.User;
import com.authprovider.entity.UserOAuthClient;
import com.authprovider.entity.UserRadiusClient;
import com.authprovider.service.RegistrationService;
import com.authprovider.service.UserClientAssignmentService;
import com.authprovider.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.Objects;

@RequiredArgsConstructor
@RestController
@RequestMapping("/v1/api/users")
public class UserController {

    private final UserService userService;
    private final UserClientAssignmentService assignmentService;
    private RegistrationService registrationService;

    @Autowired(required = false)
    public void setRegistrationService(RegistrationService registrationService) {
        this.registrationService = registrationService;
    }

    @GetMapping("/all")
    public List<UserResponse> getAllUsers() {
        List<User> users = userService.getAllUsers();
        if (users.isEmpty() || assignmentService == null) {
            return users.stream().map(UserResponse::from).toList();
        }
        List<Long> userIds = users.stream().map(User::getId).filter(Objects::nonNull).toList();
        Map<Long, List<UserRadiusClient>> radiusByUser = assignmentService.getRadiusAssignmentsByUserIds(userIds);
        Map<Long, List<UserOAuthClient>> oauthByUser = assignmentService.getOAuthAssignmentsByUserIds(userIds);
        return users.stream()
                .map(u -> UserResponse.from(
                        u,
                        radiusByUser.getOrDefault(u.getId(), List.of()).stream()
                                .map(ClientAssignmentResponse::from).toList(),
                        oauthByUser.getOrDefault(u.getId(), List.of()).stream()
                                .map(ClientAssignmentResponse::from).toList()))
                .toList();
    }

    @GetMapping("/{id}")
    public UserResponse getUserById(@PathVariable Long id) {
        return toResponse(userService.getUserOrThrow(id));
    }

    @PostMapping("/create")
    public UserResponse createUser(@RequestBody UserRequest request) {
        return toResponse(userService.createUser(request));
    }

    @PostMapping("/register")
    public ResponseEntity<UserRegistrationResponse> registerUser(
            @RequestBody(required = false) UserRegistrationRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .cacheControl(CacheControl.noStore())
                .header(HttpHeaders.PRAGMA, "no-cache")
                .body(registrationService.registerUser(request));
    }

    @PutMapping("/{id}")
    public UserResponse updateUser(@PathVariable Long id, @RequestBody UserRequest request) {
        return toResponse(userService.updateUser(id, request));
    }

    @DeleteMapping("/{id}")
    public void deleteUser(@PathVariable Long id) {
        userService.deleteUser(id);
    }

    // ---- RADIUS client assignments (administrators only) -------------------------------------------

    @GetMapping("/{userId}/radius-clients")
    public List<ClientAssignmentResponse> getRadiusClients(@PathVariable Long userId) {
        return assignmentService.getRadiusAssignments(userId).stream().map(ClientAssignmentResponse::from).toList();
    }

    @GetMapping("/{userId}/radius-clients/{clientId}")
    public ClientAssignmentResponse getRadiusClient(@PathVariable Long userId, @PathVariable Long clientId) {
        return ClientAssignmentResponse.from(assignmentService.getRadiusAssignment(userId, clientId));
    }

    @PutMapping("/{userId}/radius-clients/{clientId}")
    public ClientAssignmentResponse putRadiusClient(@PathVariable Long userId, @PathVariable Long clientId,
                                                    @RequestBody(required = false) ClientAssignmentRequest request) {
        return ClientAssignmentResponse.from(assignmentService.putRadiusAssignment(userId, clientId, request));
    }

    @DeleteMapping("/{userId}/radius-clients/{clientId}")
    public void deleteRadiusClient(@PathVariable Long userId, @PathVariable Long clientId) {
        assignmentService.deleteRadiusAssignment(userId, clientId);
    }

    // ---- OAuth 2.0 client assignments (administrators only) ----------------------------------------

    @GetMapping("/{userId}/oauth-clients")
    public List<ClientAssignmentResponse> getOAuthClients(@PathVariable Long userId) {
        return assignmentService.getOAuthAssignments(userId).stream().map(ClientAssignmentResponse::from).toList();
    }

    @GetMapping("/{userId}/oauth-clients/{clientId}")
    public ClientAssignmentResponse getOAuthClient(@PathVariable Long userId, @PathVariable Long clientId) {
        return ClientAssignmentResponse.from(assignmentService.getOAuthAssignment(userId, clientId));
    }

    @PutMapping("/{userId}/oauth-clients/{clientId}")
    public ClientAssignmentResponse putOAuthClient(@PathVariable Long userId, @PathVariable Long clientId,
                                                   @RequestBody(required = false) ClientAssignmentRequest request) {
        return ClientAssignmentResponse.from(assignmentService.putOAuthAssignment(userId, clientId, request));
    }

    @DeleteMapping("/{userId}/oauth-clients/{clientId}")
    public void deleteOAuthClient(@PathVariable Long userId, @PathVariable Long clientId) {
        assignmentService.deleteOAuthAssignment(userId, clientId);
    }

    // ---- helpers -----------------------------------------------------------------------------------

    private UserResponse toResponse(User user) {
        if (user == null) {
            return null;
        }
        if (user.getId() == null || assignmentService == null) {
            return UserResponse.from(user);
        }
        return UserResponse.from(user,
                assignmentService.getRadiusAssignments(user.getId()).stream()
                        .map(ClientAssignmentResponse::from).toList(),
                assignmentService.getOAuthAssignments(user.getId()).stream()
                        .map(ClientAssignmentResponse::from).toList());
    }
}
