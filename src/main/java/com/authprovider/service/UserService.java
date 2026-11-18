package com.authprovider.service;

import com.authprovider.dto.UserRequest;
import com.authprovider.entity.User;
import com.authprovider.exception.BadRequestException;
import com.authprovider.exception.ResourceNotFoundException;

import java.util.List;

public interface UserService {
    List<User> getAllUsers();
    User getUserById(Long id);
    User saveUser(User user);
    User createUser(UserRequest request);
    User updateUser(Long id, UserRequest request);
    void deleteUser(Long id);
    List<User> findByUsernameIgnoreCase(String username);
    List<User> findAllByUsernameIgnoreCase(String username);

    default User getUserOrThrow(Long id) {
        User user = getUserById(id);
        if (user == null) {
            throw new ResourceNotFoundException("User not found: " + id);
        }
        return user;
    }

    default User updateUser(Long id, User user) {
        if (user == null) {
            throw new BadRequestException("User payload is required");
        }
        getUserOrThrow(id);
        user.setId(id);
        return saveUser(user);
    }
}
