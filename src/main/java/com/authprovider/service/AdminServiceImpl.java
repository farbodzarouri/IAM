package com.authprovider.service;

import com.authprovider.dto.AdminRequest;
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
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Objects;

/**
 * Default implementation of {@link AdminService}.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AdminServiceImpl implements AdminService {

    private final AdminRepository adminRepository;
    private final PersonRepository personRepository;
    private final OtpTokenRepository otpTokenRepository;
    private final UserRepository userRepository;
    private final AccountLockoutService lockoutService;
    private final OtpUsageStore otpUsageStore;
    private final PasswordService passwordService;
    private final Clock clock;

    @Override
    public List<Admin> getAllAdmins() {
        return adminRepository.findAll();
    }

    @Override
    public Admin getAdminById(Long id) {
        return id == null ? null : adminRepository.findById(id).orElse(null);
    }

    @Override
    public Admin getAdminOrThrow(Long id) {
        if (id == null) {
            throw new ResourceNotFoundException("Admin not found: null");
        }
        return adminRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Admin not found: " + id));
    }

    @Override
    public List<Admin> findAllByUsernameIgnoreCase(String username) {
        if (username == null || username.isBlank()) {
            return List.of();
        }
        return adminRepository.findAllByUsernameIgnoreCase(username.trim());
    }

    @Override
    @Transactional
    public Admin createAdmin(AdminRequest request) {
        if (request == null || request.getUsername() == null || request.getUsername().isBlank()) {
            throw new BadRequestException("Admin username is required");
        }
        String username = request.getUsername().trim();
        ensureUniqueUsername(username, null);

        Person person = request.getPersonId() == null ? null : resolvePersonOrBadRequest(request.getPersonId());
        OtpToken token = request.getOtpTokenId() == null ? null : resolveTokenOrBadRequest(request.getOtpTokenId());
        if (person == null && token != null) {
            person = token.getPerson();
        }
        validateTokenOwnership(token, person);

        if (person != null && person.getId() != null) {
            validateUserCredentialSeparation(person.getId(), username, request.getPassword());
        }
        if (person == null) {
            String displayName = request.getDisplayName() == null || request.getDisplayName().isBlank()
                    ? username
                    : request.getDisplayName().trim();
            person = personRepository.save(Person.builder()
                    .displayName(displayName)
                    .enabled(true)
                    .build());
        }

        Instant now = now();
        Admin admin = Admin.builder()
                .username(username)
                .password(passwordService.encode(request.getPassword()))
                .person(person)
                .otpToken(token)
                .enabled(request.getEnabled() == null || request.getEnabled())
                .createdAt(now)
                .updatedAt(now)
                .build();
        return adminRepository.saveAndFlush(admin);
    }

    @Override
    @Transactional
    public Admin updateAdmin(Long id, AdminRequest request) {
        Admin existing = getAdminOrThrow(id);
        if (request == null) {
            throw new BadRequestException("Admin payload is required");
        }
        String username = request.getUsername() != null ? request.getUsername().trim() : existing.getUsername();
        if (username == null || username.isEmpty()) {
            throw new BadRequestException("Admin username is required");
        }
        ensureUniqueUsername(username, id);

        Person person = request.getPersonId() != null
                ? resolvePersonOrBadRequest(request.getPersonId())
                : existing.getPerson();
        OtpToken token = request.getOtpTokenId() != null
                ? resolveTokenOrBadRequest(request.getOtpTokenId())
                : existing.getOtpToken();
        if (person == null && token != null) {
            person = token.getPerson();
        }
        validateTokenOwnership(token, person);

        String candidatePassword = request.getPassword() != null && !request.getPassword().isBlank()
                ? request.getPassword()
                : existing.getPassword();
        if (person != null && person.getId() != null) {
            validateUserCredentialSeparation(person.getId(), username, candidatePassword);
        }
        if (person == null) {
            String displayName = request.getDisplayName() == null || request.getDisplayName().isBlank()
                    ? username
                    : request.getDisplayName().trim();
            person = personRepository.save(Person.builder()
                    .displayName(displayName)
                    .enabled(true)
                    .build());
        }

        Instant now = now();
        existing.setUsername(username);
        existing.setPassword(passwordService.encode(candidatePassword));
        existing.setPerson(person);
        existing.setOtpToken(token);
        if (request.getEnabled() != null) {
            existing.setEnabled(request.getEnabled());
        }
        if (existing.getCreatedAt() == null) {
            existing.setCreatedAt(now);
        }
        existing.setUpdatedAt(now);
        return adminRepository.saveAndFlush(existing);
    }

    @Override
    @Transactional
    public Admin saveAdmin(Admin admin) {
        if (admin == null || admin.getUsername() == null || admin.getUsername().isBlank()) {
            throw new BadRequestException("Admin username is required");
        }
        String username = admin.getUsername().trim();
        admin.setUsername(username);
        ensureUniqueUsername(username, admin.getId());

        if (admin.getId() != null) {
            Admin existing = getAdminOrThrow(admin.getId());
            if (admin.getPassword() == null || admin.getPassword().isBlank()) {
                admin.setPassword(existing.getPassword());
            }
            if (admin.getPerson() == null) {
                admin.setPerson(existing.getPerson());
            }
            if (admin.getOtpToken() == null) {
                admin.setOtpToken(existing.getOtpToken());
            }
            if (admin.getCreatedAt() == null) {
                admin.setCreatedAt(existing.getCreatedAt());
            }
        }

        Person person = admin.getPerson();
        OtpToken token = admin.getOtpToken();
        if (person == null && token != null) {
            person = token.getPerson();
        }
        validateTokenOwnership(token, person);

        if (person != null && person.getId() != null) {
            validateUserCredentialSeparation(person.getId(), username, admin.getPassword());
        }
        if (person == null) {
            person = personRepository.save(Person.builder()
                    .displayName(username)
                    .enabled(true)
                    .build());
        } else if (person.getId() == null) {
            person = personRepository.save(person);
        }
        admin.setPerson(person);

        Instant now = now();
        if (admin.getCreatedAt() == null) {
            admin.setCreatedAt(now);
        }
        admin.setUpdatedAt(now);
        admin.setPassword(passwordService.encode(admin.getPassword()));
        return adminRepository.saveAndFlush(admin);
    }

    @Override
    @Transactional
    public void deleteAdmin(Long id) {
        Admin existing = getAdminOrThrow(id);
        Long tokenId = existing.getOtpToken() != null ? existing.getOtpToken().getId() : null;
        if (lockoutService != null) {
            lockoutService.recordAdminSuccess(id);
        }
        adminRepository.delete(existing);
        if (tokenId != null && otpUsageStore != null && !isTokenReferenced(tokenId)) {
            otpUsageStore.forgetToken(tokenId);
        }
    }

    private void ensureUniqueUsername(String username, Long excludeId) {
        for (Admin other : adminRepository.findAllByUsernameIgnoreCase(username)) {
            if (excludeId == null || !Objects.equals(other.getId(), excludeId)) {
                throw new ConflictException("Admin username already exists: " + username);
            }
        }
    }

    private Person resolvePersonOrBadRequest(Long personId) {
        return personRepository.findById(personId)
                .orElseThrow(() -> new BadRequestException("Person not found: " + personId));
    }

    private OtpToken resolveTokenOrBadRequest(Long otpTokenId) {
        return otpTokenRepository.findById(otpTokenId)
                .orElseThrow(() -> new BadRequestException("OTP token not found: " + otpTokenId));
    }

    private static void validateTokenOwnership(OtpToken token, Person person) {
        if (token == null || person == null) {
            return;
        }
        Long tokenPersonId = token.getPerson() == null ? null : token.getPerson().getId();
        if (!Objects.equals(tokenPersonId, person.getId())) {
            throw new BadRequestException("OTP token does not belong to the admin's person");
        }
    }

    private void validateUserCredentialSeparation(Long personId, String adminUsername, String candidatePassword) {
        List<User> users = userRepository.findByPersonId(personId);
        for (User user : users) {
            if (CredentialConflictChecker.sameOrOverlappingUsername(adminUsername, user.getUsername())) {
                throw new BadRequestException(
                        "Admin and User accounts of the same person must have distinct usernames");
            }
            if (CredentialConflictChecker.passwordMatches(passwordService, user.getPassword(), candidatePassword)) {
                throw new BadRequestException(
                        "Admin and User accounts of the same person must have separate passwords");
            }
        }
    }

    private boolean isTokenReferenced(Long tokenId) {
        return !adminRepository.findByOtpTokenId(tokenId).isEmpty()
                || !userRepository.findByOtpTokenId(tokenId).isEmpty();
    }

    private Instant now() {
        return clock == null ? Instant.now() : clock.instant();
    }
}
