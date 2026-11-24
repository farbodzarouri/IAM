package com.authprovider.service;

import com.authprovider.dto.PersonRequest;
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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.function.Supplier;
import java.util.regex.Pattern;

/**
 * Default implementation of {@link PersonService}.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class PersonServiceImpl implements PersonService {

    private static final int MAX_NAME_PART_LENGTH = 128;
    private static final int MAX_DISPLAY_NAME_LENGTH = 256;
    private static final int MAX_EMAIL_LENGTH = 256;
    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$");
    private static final Pattern MOBILE_PATTERN = Pattern.compile("^\\+?[0-9]{7,20}$");
    private static final Pattern NATIONAL_CODE_PATTERN = Pattern.compile("^[A-Za-z0-9-]{5,32}$");

    private final PersonRepository personRepository;
    private final OtpTokenRepository otpTokenRepository;
    private final UserRepository userRepository;
    private final SecretGenerator secretGenerator;
    private final AccountLockoutService lockoutService;
    private final OtpUsageStore otpUsageStore;
    private AdminRepository adminRepository;
    private TransactionTemplate transactionTemplate;

    @Autowired(required = false)
    public void setAdminRepository(AdminRepository adminRepository) {
        this.adminRepository = adminRepository;
    }

    @Autowired(required = false)
    public void setTransactionManager(PlatformTransactionManager transactionManager) {
        this.transactionTemplate = transactionManager == null ? null : new TransactionTemplate(transactionManager);
    }

    @Override
    public List<Person> getAllPersons() {
        return personRepository.findAll();
    }

    @Override
    public Person getPersonById(Long id) {
        return id == null ? null : personRepository.findById(id).orElse(null);
    }

    @Override
    public Person getPersonOrThrow(Long id) {
        if (id == null) {
            throw new ResourceNotFoundException("Person not found: null");
        }
        return personRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Person not found: " + id));
    }

    @Override
    public Person createPerson(Person person) {
        if (person == null) {
            throw new BadRequestException("Person payload is required");
        }
        return createPerson(PersonRequest.builder()
                .firstName(person.getFirstName())
                .lastName(person.getLastName())
                .displayName(person.getDisplayName())
                .email(person.getEmail())
                .mobile(person.getMobile())
                .nationalCode(person.getNationalCode())
                .enabled(person.isEnabled())
                .build());
    }

    @Override
    public Person createPerson(PersonRequest request) {
        if (request == null) {
            throw new BadRequestException("Person payload is required");
        }
        return executeWrite(() -> {
            Person person = Person.builder()
                    .enabled(request.getEnabled() == null || request.getEnabled())
                    .build();
            normalizeAndApply(person, null, request, true);
            return personRepository.saveAndFlush(person);
        });
    }

    @Override
    public Person updatePerson(Long id, Person updated) {
        if (updated == null) {
            throw new BadRequestException("Person payload is required");
        }
        return updatePerson(id, PersonRequest.builder()
                .firstName(updated.getFirstName())
                .lastName(updated.getLastName())
                .displayName(updated.getDisplayName())
                .email(updated.getEmail() == null ? "" : updated.getEmail())
                .mobile(updated.getMobile())
                .nationalCode(updated.getNationalCode())
                .enabled(updated.isEnabled())
                .build());
    }

    @Override
    public Person updatePerson(Long id, PersonRequest request) {
        if (request == null) {
            throw new BadRequestException("Person payload is required");
        }
        return executeWrite(() -> {
            Person existing = getPersonOrThrow(id);
            boolean wasEnabled = existing.isEnabled();
            normalizeAndApply(existing, id, request, false);
            if (request.getEnabled() != null) {
                existing.setEnabled(request.getEnabled());
            }
            Person saved = personRepository.saveAndFlush(existing);
            if (wasEnabled && !saved.isEnabled()) {
                log.info("Person id {} disabled; invalidating pending authentication sessions", id);
                invalidateLinkedUserSessions(id);
            }
            return saved;
        });
    }

    @Override
    public void deletePerson(Long id) {
        executeWrite(() -> {
            Person existing = getPersonOrThrow(id);
            if (!userRepository.findByPersonId(id).isEmpty()
                    || (adminRepository != null && !adminRepository.findByPersonId(id).isEmpty())) {
                throw new ConflictException("Cannot delete person " + id + " while user or admin accounts are linked");
            }
            List<OtpToken> tokens = otpTokenRepository.findByPersonId(id);
            for (OtpToken token : tokens) {
                if (otpUsageStore != null && token.getId() != null) {
                    otpUsageStore.forgetToken(token.getId());
                }
            }
            if (!tokens.isEmpty()) {
                otpTokenRepository.deleteAll(tokens);
                otpTokenRepository.flush();
            }
            personRepository.delete(existing);
            personRepository.flush();
            return null;
        });
    }

    @Override
    @Transactional
    public OtpToken createToken(Long personId, String label, String secret) {
        Person person = getPersonOrThrow(personId);
        String effectiveSecret = (secret == null || secret.isBlank())
                ? secretGenerator.generateSecret()
                : secret.trim();
        OtpToken token = OtpToken.builder()
                .person(person)
                .label(label == null || label.isBlank() ? "authenticator" : label.trim())
                .secret(effectiveSecret)
                .enabled(true)
                .build();
        return otpTokenRepository.save(token);
    }

    @Override
    public List<OtpToken> getTokensForPerson(Long personId) {
        getPersonOrThrow(personId);
        return otpTokenRepository.findByPersonId(personId);
    }

    @Override
    public OtpToken getTokenById(Long tokenId) {
        return tokenId == null ? null : otpTokenRepository.findById(tokenId).orElse(null);
    }

    @Override
    public OtpToken getTokenOrThrow(Long tokenId) {
        if (tokenId == null) {
            throw new ResourceNotFoundException("OTP token not found: null");
        }
        return otpTokenRepository.findById(tokenId)
                .orElseThrow(() -> new ResourceNotFoundException("OTP token not found: " + tokenId));
    }

    @Override
    @Transactional
    public OtpToken rotateTokenSecret(Long tokenId) {
        OtpToken token = getTokenOrThrow(tokenId);
        String nextSecret = secretGenerator.generateSecret();
        token.setSecret(nextSecret);
        OtpToken saved = otpTokenRepository.save(token);
        for (User user : userRepository.findByOtpTokenId(tokenId)) {
            if (lockoutService != null && user.getId() != null) {
                lockoutService.invalidatePendingSessions(user.getId());
            }
        }
        if (otpUsageStore != null) {
            otpUsageStore.resetTokenOcraChallenges(tokenId);
        }
        return saved;
    }

    @Override
    @Transactional
    public void setTokenEnabled(Long tokenId, boolean enabled) {
        OtpToken token = getTokenOrThrow(tokenId);
        if (token.isEnabled() == enabled) {
            return;
        }
        token.setEnabled(enabled);
        otpTokenRepository.save(token);
        if (!enabled) {
            for (User user : userRepository.findByOtpTokenId(tokenId)) {
                if (lockoutService != null && user.getId() != null) {
                    lockoutService.invalidatePendingSessions(user.getId());
                }
            }
        }
    }

    private void normalizeAndApply(Person target, Long excludeId, PersonRequest request, boolean isCreate) {
        String oldDerived = deriveFullName(target.getFirstName(), target.getLastName());

        if (request.getFirstName() != null) {
            target.setFirstName(normalizeNamePart(request.getFirstName(), "firstName", MAX_NAME_PART_LENGTH));
        }
        if (request.getLastName() != null) {
            target.setLastName(normalizeNamePart(request.getLastName(), "lastName", MAX_NAME_PART_LENGTH));
        }

        String newDerived = deriveFullName(target.getFirstName(), target.getLastName());
        if (request.getDisplayName() != null) {
            String trimmedDisplay = normalizeNamePart(request.getDisplayName(), "displayName", MAX_DISPLAY_NAME_LENGTH);
            if (trimmedDisplay != null) {
                target.setDisplayName(trimmedDisplay);
            } else if (newDerived != null) {
                target.setDisplayName(newDerived);
            } else {
                throw new BadRequestException("Either displayName or firstName/lastName is required");
            }
        } else if (isCreate) {
            if (newDerived == null) {
                throw new BadRequestException("Either displayName or firstName/lastName is required");
            }
            target.setDisplayName(validateMaxLength(newDerived, "displayName", MAX_DISPLAY_NAME_LENGTH));
        } else if ((request.getFirstName() != null || request.getLastName() != null)
                && newDerived != null
                && (Objects.equals(target.getDisplayName(), oldDerived)
                || target.getDisplayName() == null
                || target.getDisplayName().isBlank())) {
            target.setDisplayName(validateMaxLength(newDerived, "displayName", MAX_DISPLAY_NAME_LENGTH));
        }

        if (request.getEmail() != null) {
            String normalizedEmail = normalizeEmail(request.getEmail());
            if (normalizedEmail != null) {
                personRepository.findByEmailIgnoreCase(normalizedEmail)
                        .filter(other -> !Objects.equals(other.getId(), excludeId))
                        .ifPresent(other -> {
                            throw new ConflictException("Person with email already exists: " + normalizedEmail);
                        });
            }
            target.setEmail(normalizedEmail);
        }

        if (request.getMobile() != null) {
            String normalizedMobile = normalizeMobile(request.getMobile());
            if (normalizedMobile != null) {
                personRepository.findByMobile(normalizedMobile)
                        .filter(other -> !Objects.equals(other.getId(), excludeId))
                        .ifPresent(other -> {
                            throw new ConflictException("Person with mobile already exists: " + normalizedMobile);
                        });
            }
            target.setMobile(normalizedMobile);
        }

        if (request.getNationalCode() != null) {
            String normalizedCode = normalizeNationalCode(request.getNationalCode());
            if (normalizedCode != null) {
                personRepository.findByNationalCodeIgnoreCase(normalizedCode)
                        .filter(other -> !Objects.equals(other.getId(), excludeId))
                        .ifPresent(other -> {
                            throw new ConflictException("Person with nationalCode already exists: " + normalizedCode);
                        });
            }
            target.setNationalCode(normalizedCode);
        }
    }

    private <T> T executeWrite(Supplier<T> work) {
        if (transactionTemplate == null || TransactionSynchronizationManager.isActualTransactionActive()) {
            try {
                return work.get();
            } catch (DataIntegrityViolationException | OptimisticLockingFailureException e) {
                throw new ConflictException("Person profile conflicts with an existing record");
            }
        }
        try {
            return transactionTemplate.execute(status -> work.get());
        } catch (DataIntegrityViolationException | OptimisticLockingFailureException e) {
            throw new ConflictException("Person profile conflicts with an existing record");
        }
    }

    private static String normalizeNamePart(String raw, String field, int maxLength) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        return validateMaxLength(raw.trim(), field, maxLength);
    }

    private static String validateMaxLength(String value, String field, int maxLength) {
        if (value.length() > maxLength) {
            throw new BadRequestException(field + " must not exceed " + maxLength + " characters");
        }
        return value;
    }

    private static String deriveFullName(String firstName, String lastName) {
        boolean hasFirst = firstName != null && !firstName.isBlank();
        boolean hasLast = lastName != null && !lastName.isBlank();
        if (hasFirst && hasLast) {
            return firstName.trim() + " " + lastName.trim();
        }
        if (hasFirst) {
            return firstName.trim();
        }
        if (hasLast) {
            return lastName.trim();
        }
        return null;
    }

    private static String normalizeEmail(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        String normalized = raw.trim().toLowerCase(Locale.ROOT);
        if (normalized.length() > MAX_EMAIL_LENGTH || !EMAIL_PATTERN.matcher(normalized).matches()) {
            throw new BadRequestException("Invalid email format");
        }
        return normalized;
    }

    private static String normalizeMobile(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        String stripped = raw.trim().replaceAll("[\\s()-]+", "");
        if (!MOBILE_PATTERN.matcher(stripped).matches()) {
            throw new BadRequestException("Invalid mobile number format");
        }
        return stripped;
    }

    private static String normalizeNationalCode(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        String normalized = raw.trim().toUpperCase(Locale.ROOT);
        if (!NATIONAL_CODE_PATTERN.matcher(normalized).matches()) {
            throw new BadRequestException("Invalid nationalCode format");
        }
        return normalized;
    }

    private void invalidateLinkedUserSessions(Long personId) {
        if (lockoutService == null) {
            return;
        }
        for (User user : userRepository.findByPersonId(personId)) {
            if (user.getId() != null) {
                lockoutService.invalidatePendingSessions(user.getId());
            }
        }
    }
}
