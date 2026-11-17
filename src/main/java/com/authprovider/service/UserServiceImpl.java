package com.authprovider.service;

import com.authprovider.entity.User;
import com.authprovider.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Objects;

@Slf4j
@Service
public class UserServiceImpl implements UserService, AccountSecuritySupport {

    private final UserRepository userRepository;
    private final AccountLockoutService lockoutService;
    private final OtpUsageStore otpUsageStore;

    public UserServiceImpl(UserRepository userRepository) {
        this(userRepository, null, null);
    }

    @Autowired
    public UserServiceImpl(UserRepository userRepository, AccountLockoutService lockoutService,
                           OtpUsageStore otpUsageStore) {
        this.userRepository = userRepository;
        this.lockoutService = lockoutService;
        this.otpUsageStore = otpUsageStore;
    }

    @Override
    public AccountLockoutService accountLockoutService() {
        return lockoutService;
    }

    @Override
    public OtpUsageStore otpUsageStore() {
        return otpUsageStore;
    }

    @Override
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    @Override
    public User getUserById(Long id) {
        if (id == null) {
            return null;
        }
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
        CredentialSnapshot before = user.getId() == null ? null : snapshot(user.getId());
        User saved = userRepository.save(user);
        if (before != null) {
            User after = saved == null ? user : saved;
            boolean secretChanged = !Objects.equals(before.secret(), after.getSecret());
            boolean passwordChanged = !Objects.equals(before.password(), after.getPassword());
            boolean renamed = !Objects.equals(before.username(), after.getUsername());
            if (secretChanged || passwordChanged || renamed) {
                log.info("Credentials of user id {} changed; invalidating pending authentication sessions",
                        after.getId());
                invalidatePendingSessions(after.getId());
            }
            if (secretChanged && otpUsageStore != null) {
                otpUsageStore.resetOcraChallenges(after.getId());
            }
        }
        return saved;
    }

    @Override
    public void deleteUser(Long id) {
        invalidatePendingSessions(id);
        if (otpUsageStore != null) {
            otpUsageStore.forgetUser(id);
        }
        if (lockoutService != null) {
            lockoutService.recordSuccess(id);
        }
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

    private void invalidatePendingSessions(Long userId) {
        if (lockoutService != null && userId != null) {
            lockoutService.invalidatePendingSessions(userId);
        }
    }

    private record CredentialSnapshot(String username, String password, String secret) {
    }

    private CredentialSnapshot snapshot(Long id) {
        List<Object[]> rows;
        try {
            rows = userRepository.findCredentialSnapshot(id);
        } catch (RuntimeException e) {
            log.warn("Unable to read stored credentials of user id {}", id, e);
            return new CredentialSnapshot(null, null, null);
        }
        if (rows == null || rows.isEmpty() || rows.get(0) == null || rows.get(0).length < 3) {
            return null;
        }
        Object[] row = rows.get(0);
        return new CredentialSnapshot((String) row[0], (String) row[1], (String) row[2]);
    }
}
