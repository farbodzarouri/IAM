package com.authprovider.service;

import com.authprovider.entity.User;
import com.authprovider.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;

    @Override
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    @Override
    public User getUserById(Long id) {
        return userRepository.findById(id).orElse(null);
    }

    @Override
    public User saveUser(User user) {
        if (user == null) {
            return null;
        }
        if (user.getUsername() != null) {
            user.setUsername(user.getUsername().trim());
        }
        if (user.getId() == null && user.getUsername() != null) {
            List<User> existing = userRepository.findAllByUsernameIgnoreCase(user.getUsername());
            if (!existing.isEmpty()) {
                throw new IllegalArgumentException("Username already exists: " + user.getUsername());
            }
        }
        return userRepository.save(user);
    }

    @Override
    public void deleteUser(Long id) {
        userRepository.deleteById(id);
    }

    @Override
    public List<User> findByUsernameIgnoreCase(String username) {
        return findAllByUsernameIgnoreCase(username);
    }

    @Override
    public List<User> findAllByUsernameIgnoreCase(String username) {
        if (username == null || username.isBlank()) {
            return List.of();
        }
        return userRepository.findAllByUsernameIgnoreCase(username);
    }
}
