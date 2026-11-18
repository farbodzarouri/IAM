package com.authprovider.service;

import com.authprovider.dto.UserRequest;
import com.authprovider.entity.Admin;
import com.authprovider.entity.OtpToken;
import com.authprovider.entity.Person;
import com.authprovider.entity.User;
import com.authprovider.exception.BadRequestException;
import com.authprovider.exception.ConflictException;
import com.authprovider.exception.ResourceNotFoundException;
import com.authprovider.repository.AdminRepository;
import com.authprovider.repository.OtpTokenRepository;
import com.authprovider.repository.PersonRepository;
import com.authprovider.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Objects;

@Slf4j
@Service
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final PersonRepository personRepository;
    private final OtpTokenRepository otpTokenRepository;
    private final AdminRepository adminRepository;
    private final AccountLockoutService lockoutService;
    private final OtpUsageStore otpUsageStore;
    private final PasswordService passwordService;

    @Autowired
    public UserServiceImpl(UserRepository userRepository,
                           PersonRepository personRepository,
                           OtpTokenRepository otpTokenRepository,
                           AdminRepository adminRepository,
                           AccountLockoutService lockoutService,
                           OtpUsageStore otpUsageStore,
                           PasswordService passwordService) {
        this.userRepository = userRepository;
        this.personRepository = personRepository;
        this.otpTokenRepository = otpTokenRepository;
        this.adminRepository = adminRepository;
        this.lockoutService = lockoutService;
        this.otpUsageStore = otpUsageStore;
        this.passwordService = passwordService;
        if (this.lockoutService != null && this.userRepository != null) {
            this.lockoutService.addTokenLockListener(this::invalidateUsersForToken);
        }
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
    public User getUserOrThrow(Long id) {
        if (id == null) {
            throw new ResourceNotFoundException("User not found: null");
        }
        return userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User not found: " + id));
    }

    @Override
    @Transactional
    public User createUser(UserRequest request) {
        if (request == null || request.getUsername() == null || request.getUsername().isBlank()) {
            throw new BadRequestException("Username is required");
        }
        User user = User.builder()
                .username(request.getUsername().trim())
                .password(request.getPassword())
                .secret(request.getSecret())
                .enabled(request.getEnabled() == null || request.getEnabled())
                .authMode(request.getAuthMode())
                .build();
        return persistUser(user, request.getSecret(), request.getPersonId(), request.getOtpTokenId(), null);
    }

    @Override
    @Transactional
    public User updateUser(Long id, UserRequest request) {
        if (request == null) {
            throw new BadRequestException("User payload is required");
        }
        CredentialSnapshot before = snapshot(id);
        User existing = getUserOrThrow(id);
        String username = request.getUsername() != null ? request.getUsername().trim() : existing.getUsername();
        if (username == null || username.isEmpty()) {
            throw new BadRequestException("Username is required");
        }
        User updated = User.builder()
                .id(id)
                .username(username)
                .password(request.getPassword() != null && !request.getPassword().isBlank()
                        ? request.getPassword() : existing.getPassword())
                .person(existing.getPerson())
                .otpToken(existing.getOtpToken())
                .enabled(request.getEnabled() != null ? request.getEnabled() : existing.isEnabled())
                .authMode(request.getAuthMode() != null ? request.getAuthMode() : existing.getAuthMode())
                .build();
        String requestedSecret = request.getSecret() != null && !request.getSecret().isBlank()
                ? request.getSecret() : existing.getRawSecret();
        return persistUser(updated, requestedSecret, request.getPersonId(), request.getOtpTokenId(), before);
    }

    @Override
    @Transactional
    public User saveUser(User user) {
        if (user == null) {
            throw new BadRequestException("User payload is required");
        }
        if (user.getUsername() != null) {
            user.setUsername(user.getUsername().trim());
        }
        CredentialSnapshot before = user.getId() == null ? null : snapshot(user.getId());
        User existingEntity = user.getId() == null ? null : getUserOrThrow(user.getId());
        if (existingEntity != null) {
            if (user.getPassword() == null || user.getPassword().isBlank()) {
                user.setPassword(existingEntity.getPassword());
            }
            if (user.getPerson() == null) {
                user.setPerson(existingEntity.getPerson());
            }
            if (user.getOtpToken() == null && (user.getRawSecret() == null || user.getRawSecret().isBlank())) {
                user.setOtpToken(existingEntity.getOtpToken());
                user.setSecret(existingEntity.getRawSecret());
            }
            if (user.getAuthMode() == null) {
                user.setAuthMode(existingEntity.getAuthMode());
            }
        }
        return persistUser(user, user.getRawSecret(), null, null, before);
    }

    private User persistUser(User user, String rawSecret, Long requestedPersonId,
                             Long requestedOtpTokenId, CredentialSnapshot before) {
        if (user.getUsername() != null) {
            ensureUniqueUsername(user.getUsername(), user.getId());
        }

        if (personRepository != null && otpTokenRepository != null) {
            resolveLinksAndValidate(user, rawSecret, requestedPersonId, requestedOtpTokenId);
        } else {
            validateAdminCredentialSeparation(user);
            user.setSecret(rawSecret);
        }

        user.setPassword(passwordService.encode(user.getPassword()));
        User saved = userRepository.save(user);
        if (before != null) {
            handlePostUpdateLifecycle(before, saved == null ? user : saved);
        }
        return saved;
    }

    private void ensureUniqueUsername(String username, Long excludeId) {
        for (User other : userRepository.findAllByUsernameIgnoreCase(username)) {
            if (excludeId == null || !Objects.equals(other.getId(), excludeId)) {
                throw new ConflictException("Username already exists: " + username);
            }
        }
    }

    private void resolveLinksAndValidate(User user, String rawSecret, Long requestedPersonId, Long requestedOtpTokenId) {
        if (requestedPersonId != null) {
            Person resolvedPerson = personRepository.findById(requestedPersonId)
                    .orElseThrow(() -> new BadRequestException("Person not found: " + requestedPersonId));
            user.setPerson(resolvedPerson);
        }
        if (requestedOtpTokenId != null) {
            OtpToken resolvedToken = otpTokenRepository.findById(requestedOtpTokenId)
                    .orElseThrow(() -> new BadRequestException("OTP token not found: " + requestedOtpTokenId));
            user.setOtpToken(resolvedToken);
        }
        if (user.getPerson() == null && user.getOtpToken() != null && user.getOtpToken().getPerson() != null) {
            user.setPerson(user.getOtpToken().getPerson());
        }
        if (user.getOtpToken() != null && user.getPerson() != null) {
            Long tokenPersonId = user.getOtpToken().getPerson() == null ? null : user.getOtpToken().getPerson().getId();
            if (!Objects.equals(tokenPersonId, user.getPerson().getId())) {
                throw new BadRequestException("OTP token does not belong to the user's person");
            }
        }

        // Validate credential separation before creating any new Person row.
        validateAdminCredentialSeparation(user);

        if (user.getPerson() == null) {
            String label = user.getUsername() == null || user.getUsername().isBlank()
                    ? "user" : user.getUsername();
            Person created = personRepository.save(Person.builder()
                    .displayName(label)
                    .enabled(true)
                    .build());
            user.setPerson(created);
        } else if (user.getPerson().getId() == null) {
            user.setPerson(personRepository.save(user.getPerson()));
        }

        if (user.getOtpToken() == null && rawSecret != null && !rawSecret.isBlank()) {
            OtpToken token = otpTokenRepository.save(OtpToken.builder()
                    .person(user.getPerson())
                    .label(user.getUsername() == null ? "authenticator" : user.getUsername())
                    .secret(rawSecret)
                    .enabled(true)
                    .build());
            user.setOtpToken(token);
            user.setSecret(null);
        } else if (user.getOtpToken() != null) {
            OtpToken token = user.getOtpToken();
            if (rawSecret != null && !rawSecret.isBlank() && !Objects.equals(rawSecret, token.getSecret())) {
                token.setSecret(rawSecret);
                token = otpTokenRepository.save(token);
                user.setOtpToken(token);
            }
            user.setSecret(null);
        } else {
            user.setSecret(null);
        }
    }

    private void handlePostUpdateLifecycle(CredentialSnapshot before, User after) {
        boolean secretChanged = !Objects.equals(before.secret(), after.getSecret());
        boolean passwordChanged = !Objects.equals(before.password(), after.getPassword());
        boolean renamed = !Objects.equals(before.username(), after.getUsername());
        boolean disabled = !after.isAccountEnabled();
        if (secretChanged || passwordChanged || renamed || disabled) {
            log.info("Credentials or status of user id {} changed; invalidating pending authentication sessions",
                    after.getId());
            invalidatePendingSessions(after.getId());
            if (secretChanged && after.getOtpToken() != null && after.getOtpToken().getId() != null) {
                invalidateUsersForToken(after.getOtpToken().getId());
            }
        }
        if (secretChanged && otpUsageStore != null) {
            otpUsageStore.resetOcraChallenges(after.getId());
            if (after.getOtpToken() != null && after.getOtpToken().getId() != null) {
                otpUsageStore.resetTokenOcraChallenges(after.getOtpToken().getId());
            }
        }
    }

    private void validateAdminCredentialSeparation(User user) {
        if (adminRepository == null || user.getPerson() == null || user.getPerson().getId() == null) {
            return;
        }
        List<Admin> admins = adminRepository.findByPersonId(user.getPerson().getId());
        for (Admin admin : admins) {
            if (CredentialConflictChecker.sameOrOverlappingUsername(user.getUsername(), admin.getUsername())) {
                throw new BadRequestException(
                        "User and Admin accounts of the same person must have distinct usernames");
            }
            if (CredentialConflictChecker.passwordMatches(passwordService, admin.getPassword(), user.getPassword())) {
                throw new BadRequestException(
                        "User and Admin accounts of the same person must have separate passwords");
            }
        }
    }

    @Override
    @Transactional
    public void deleteUser(Long id) {
        User existing = getUserOrThrow(id);
        Long tokenId = existing.getOtpToken() != null ? existing.getOtpToken().getId() : null;
        invalidatePendingSessions(id);
        if (otpUsageStore != null) {
            otpUsageStore.forgetUser(id);
        }
        if (lockoutService != null) {
            lockoutService.recordSuccess(id);
        }
        userRepository.delete(existing);
        if (tokenId != null && otpUsageStore != null && !isTokenStillReferenced(tokenId)) {
            otpUsageStore.forgetToken(tokenId);
        }
    }

    private boolean isTokenStillReferenced(Long tokenId) {
        boolean usedByUsers = !userRepository.findByOtpTokenId(tokenId).isEmpty();
        boolean usedByAdmins = adminRepository != null && !adminRepository.findByOtpTokenId(tokenId).isEmpty();
        return usedByUsers || usedByAdmins;
    }

    private void invalidateUsersForToken(Long tokenId) {
        if (tokenId == null || userRepository == null || lockoutService == null) {
            return;
        }
        for (User user : userRepository.findByOtpTokenId(tokenId)) {
            if (user.getId() != null) {
                invalidatePendingSessions(user.getId());
            }
        }
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
