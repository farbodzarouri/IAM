package com.authprovider;

import com.authprovider.dto.ClientAssignmentRequest;
import com.authprovider.entity.AuthMode;
import com.authprovider.entity.OAuthClient;
import com.authprovider.entity.RadiusClient;
import com.authprovider.entity.User;
import com.authprovider.repository.OAuthClientRepository;
import com.authprovider.repository.RadiusClientRepository;
import com.authprovider.repository.UserOAuthClientRepository;
import com.authprovider.repository.UserRadiusClientRepository;
import com.authprovider.repository.UserRepository;
import com.authprovider.service.UserClientAssignmentService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Test support: users need an enabled assignment to a RADIUS / OAuth 2.0 client before they can authenticate
 * through it. {@link #assignAll()} gives every user without one an enabled assignment to every client
 * (existing assignments are left untouched); {@link #authMode} sets the assignment authentication mode.
 */
@Component
public class TestClientAssignments {

    @Autowired
    private UserClientAssignmentService assignmentService;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private RadiusClientRepository radiusClientRepository;
    @Autowired
    private OAuthClientRepository oauthClientRepository;
    @Autowired
    private UserRadiusClientRepository radiusAssignmentRepository;
    @Autowired
    private UserOAuthClientRepository oauthAssignmentRepository;

    /** Assignment auth modes requested per user id, applied to clients created later as well. */
    private final Map<Long, AuthMode> modes = new ConcurrentHashMap<>();

    public synchronized void assignAll() {
        for (User user : userRepository.findAll()) {
            AuthMode mode = modes.get(user.getId());
            for (RadiusClient client : radiusClientRepository.findAll()) {
                if (radiusAssignmentRepository.findByUserIdAndClientId(user.getId(), client.getId()).isEmpty()) {
                    assignmentService.putRadiusAssignment(user.getId(), client.getId(), request(mode));
                }
            }
            for (OAuthClient client : oauthClientRepository.findAll()) {
                if (oauthAssignmentRepository.findByUserIdAndClientId(user.getId(), client.getId()).isEmpty()) {
                    assignmentService.putOAuthAssignment(user.getId(), client.getId(), request(mode));
                }
            }
        }
    }

    /** Sets the authentication mode of the user's assignments to every (current and future) client. */
    public synchronized User authMode(User user, AuthMode mode) {
        if (mode == null) {
            modes.remove(user.getId());
        } else {
            modes.put(user.getId(), mode);
        }
        for (RadiusClient client : radiusClientRepository.findAll()) {
            assignmentService.putRadiusAssignment(user.getId(), client.getId(), request(mode));
        }
        for (OAuthClient client : oauthClientRepository.findAll()) {
            assignmentService.putOAuthAssignment(user.getId(), client.getId(), request(mode));
        }
        return user;
    }

    private static ClientAssignmentRequest request(AuthMode mode) {
        return ClientAssignmentRequest.builder().enabled(true).authMode(mode).build();
    }
}
