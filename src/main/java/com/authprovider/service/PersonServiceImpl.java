package com.authprovider.service;

import com.authprovider.entity.OtpToken;
import com.authprovider.entity.Person;
import com.authprovider.entity.User;
import com.authprovider.exception.BadRequestException;
import com.authprovider.exception.ResourceNotFoundException;
import com.authprovider.repository.OtpTokenRepository;
import com.authprovider.repository.PersonRepository;
import com.authprovider.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * Default implementation of {@link PersonService}.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class PersonServiceImpl implements PersonService {

    private final PersonRepository personRepository;
    private final OtpTokenRepository otpTokenRepository;
    private final UserRepository userRepository;
    private final SecretGenerator secretGenerator;
    private final AccountLockoutService lockoutService;
    private final OtpUsageStore otpUsageStore;

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
    @Transactional
    public Person createPerson(Person person) {
        if (person == null || person.getDisplayName() == null || person.getDisplayName().isBlank()) {
            throw new BadRequestException("Display name is required");
        }
        person.setId(null);
        person.setDisplayName(person.getDisplayName().trim());
        if (person.getEmail() != null) {
            person.setEmail(person.getEmail().trim());
        }
        return personRepository.save(person);
    }

    @Override
    @Transactional
    public Person updatePerson(Long id, Person updated) {
        Person existing = getPersonOrThrow(id);
        if (updated == null) {
            throw new BadRequestException("Person payload is required");
        }
        boolean wasEnabled = existing.isEnabled();
        if (updated.getDisplayName() != null && !updated.getDisplayName().isBlank()) {
            existing.setDisplayName(updated.getDisplayName().trim());
        }
        if (updated.getEmail() != null) {
            existing.setEmail(updated.getEmail().isBlank() ? null : updated.getEmail().trim());
        }
        existing.setEnabled(updated.isEnabled());
        Person saved = personRepository.save(existing);
        if (wasEnabled && !saved.isEnabled()) {
            log.info("Person id {} disabled; invalidating pending authentication sessions", id);
            invalidateLinkedUserSessions(id);
        }
        return saved;
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
            if (user.getRawSecret() != null) {
                user.setSecret(null);
                userRepository.save(user);
            }
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
