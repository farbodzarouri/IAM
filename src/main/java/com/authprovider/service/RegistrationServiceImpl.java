package com.authprovider.service;

import com.authprovider.dto.ClientAssignmentResponse;
import com.authprovider.dto.PersonResponse;
import com.authprovider.dto.UserRegistrationRequest;
import com.authprovider.dto.UserRegistrationResponse;
import com.authprovider.dto.UserResponse;
import com.authprovider.entity.Admin;
import com.authprovider.entity.OtpToken;
import com.authprovider.entity.Person;
import com.authprovider.entity.User;
import com.authprovider.exception.BadRequestException;
import com.authprovider.exception.ConflictException;
import com.authprovider.repository.AdminRepository;
import com.authprovider.repository.OtpTokenRepository;
import com.authprovider.repository.PersonRepository;
import com.authprovider.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.List;
import java.util.Objects;

/**
 * Default {@link RegistrationService} executing the entire onboarding graph atomically.
 */
@Slf4j
@Service
public class RegistrationServiceImpl implements RegistrationService {

    private final PersonService personService;
    private final PersonRepository personRepository;
    private final OtpTokenRepository otpTokenRepository;
    private final UserRepository userRepository;
    private final AdminRepository adminRepository;
    private final PasswordService passwordService;
    private final UserClientAssignmentService assignmentService;
    private final QrCodeGenerator qrCodeGenerator;
    private final TransactionTemplate transactionTemplate;

    public RegistrationServiceImpl(PersonService personService,
                                   PersonRepository personRepository,
                                   OtpTokenRepository otpTokenRepository,
                                   UserRepository userRepository,
                                   AdminRepository adminRepository,
                                   PasswordService passwordService,
                                   UserClientAssignmentService assignmentService,
                                   QrCodeGenerator qrCodeGenerator,
                                   PlatformTransactionManager transactionManager) {
        this.personService = personService;
        this.personRepository = personRepository;
        this.otpTokenRepository = otpTokenRepository;
        this.userRepository = userRepository;
        this.adminRepository = adminRepository;
        this.passwordService = passwordService;
        this.assignmentService = assignmentService;
        this.qrCodeGenerator = qrCodeGenerator;
        this.transactionTemplate = new TransactionTemplate(transactionManager);
    }

    @Override
    public UserRegistrationResponse registerUser(UserRegistrationRequest request) {
        validateRequest(request);
        try {
            return transactionTemplate.execute(status -> executeRegistration(request));
        } catch (DataIntegrityViolationException | OptimisticLockingFailureException e) {
            throw new ConflictException("Registration conflicts with an existing user or person");
        }
    }

    private void validateRequest(UserRegistrationRequest request) {
        if (request == null || request.getUsername() == null || request.getUsername().isBlank()) {
            throw new BadRequestException("Username is required");
        }
        boolean hasPersonObj = request.getPerson() != null;
        boolean hasPersonId = request.getPersonId() != null;
        if (hasPersonObj == hasPersonId) {
            throw new BadRequestException("Specify either person or personId, not both or neither");
        }
        boolean wantsNewToken = request.getOtpToken() != null || Boolean.TRUE.equals(request.getProvisionOtpToken());
        if (request.getOtpTokenId() != null && wantsNewToken) {
            throw new BadRequestException("Specify either otpTokenId or otpToken/provisionOtpToken, not both");
        }
        if (assignmentService != null && (request.getRadiusClients() != null || request.getOauthClients() != null)) {
            assignmentService.validateAssignments(request.getRadiusClients(), request.getOauthClients());
        }
    }

    private UserRegistrationResponse executeRegistration(UserRegistrationRequest request) {
        String username = request.getUsername().trim();
        if (!userRepository.findAllByUsernameIgnoreCase(username).isEmpty()) {
            throw new ConflictException("Username already exists: " + username);
        }

        Person person = resolveOrCreatePerson(request);

        String rawPassword = (request.getPassword() == null || request.getPassword().isBlank())
                ? null : request.getPassword();
        validateAdminCredentialSeparation(person.getId(), username, rawPassword);

        TokenResolution resolvedToken = resolveOrCreateOtpToken(request, person, username);
        OtpToken token = resolvedToken.token();

        User savedUser = userRepository.saveAndFlush(User.builder()
                .username(username)
                .password(rawPassword == null ? null : passwordService.encode(rawPassword))
                .person(person)
                .otpToken(token)
                .enabled(request.getEnabled() == null || request.getEnabled())
                .build());

        if (assignmentService != null && (request.getRadiusClients() != null || request.getOauthClients() != null)) {
            assignmentService.replaceAssignments(savedUser.getId(), request.getRadiusClients(), request.getOauthClients());
        }

        List<ClientAssignmentResponse> radiusResponses = assignmentService == null ? List.of()
                : assignmentService.getRadiusAssignments(savedUser.getId()).stream()
                        .map(ClientAssignmentResponse::from).toList();
        List<ClientAssignmentResponse> oauthResponses = assignmentService == null ? List.of()
                : assignmentService.getOAuthAssignments(savedUser.getId()).stream()
                        .map(ClientAssignmentResponse::from).toList();

        UserRegistrationResponse.ProvisionedTokenInfo tokenInfo =
                buildTokenInfo(person, token, resolvedToken.newlyProvisioned());

        log.info("Registered user '{}' (id={}) linked to person id {} (otpTokenId={})",
                savedUser.getUsername(), savedUser.getId(), person.getId(), token == null ? null : token.getId());

        return UserRegistrationResponse.builder()
                .person(PersonResponse.from(person))
                .user(UserResponse.from(savedUser, radiusResponses, oauthResponses))
                .otpToken(tokenInfo)
                .build();
    }

    private Person resolveOrCreatePerson(UserRegistrationRequest request) {
        if (request.getPerson() != null) {
            return personService.createPerson(request.getPerson());
        }
        return personRepository.findById(request.getPersonId())
                .orElseThrow(() -> new BadRequestException("Person not found: " + request.getPersonId()));
    }

    private void validateAdminCredentialSeparation(Long personId, String username, String rawPassword) {
        if (adminRepository == null || personId == null) {
            return;
        }
        List<Admin> admins = adminRepository.findByPersonId(personId);
        for (Admin admin : admins) {
            if (CredentialConflictChecker.sameOrOverlappingUsername(username, admin.getUsername())) {
                throw new BadRequestException(
                        "User and Admin accounts of the same person must have distinct usernames");
            }
            if (CredentialConflictChecker.passwordMatches(passwordService, admin.getPassword(), rawPassword)) {
                throw new BadRequestException(
                        "User and Admin accounts of the same person must have separate passwords");
            }
        }
    }

    private record TokenResolution(OtpToken token, boolean newlyProvisioned) {
    }

    private TokenResolution resolveOrCreateOtpToken(UserRegistrationRequest request, Person person, String username) {
        boolean wantsNewToken = request.getOtpToken() != null || Boolean.TRUE.equals(request.getProvisionOtpToken());
        if (wantsNewToken) {
            UserRegistrationRequest.OtpTokenSpec spec = request.getOtpToken();
            String label = spec != null && spec.label() != null && !spec.label().isBlank() ? spec.label() : username;
            String secret = spec == null ? null : spec.secret();
            OtpToken created = personService.createToken(person.getId(), label, secret);
            if (spec != null && Boolean.FALSE.equals(spec.enabled())) {
                personService.setTokenEnabled(created.getId(), false);
                created = personService.getTokenOrThrow(created.getId());
            }
            return new TokenResolution(created, true);
        }
        if (request.getOtpTokenId() != null) {
            OtpToken existing = otpTokenRepository.findById(request.getOtpTokenId())
                    .orElseThrow(() -> new BadRequestException("OTP token not found: " + request.getOtpTokenId()));
            Long tokenPersonId = existing.getPerson() == null ? null : existing.getPerson().getId();
            if (!Objects.equals(tokenPersonId, person.getId())) {
                throw new BadRequestException("OTP token does not belong to the user's person");
            }
            return new TokenResolution(existing, false);
        }
        return new TokenResolution(null, false);
    }

    private UserRegistrationResponse.ProvisionedTokenInfo buildTokenInfo(
            Person person, OtpToken token, boolean newlyProvisioned) {
        if (token == null) {
            return null;
        }
        UserRegistrationResponse.ProvisionedTokenInfo.ProvisionedTokenInfoBuilder builder =
                UserRegistrationResponse.ProvisionedTokenInfo.builder()
                        .id(token.getId())
                        .personId(person.getId())
                        .label(token.getLabel())
                        .enabled(token.isEnabled());
        if (newlyProvisioned) {
            String label = person.getDisplayName() != null ? person.getDisplayName() : token.getLabel();
            String otpAuthUri = OtpProvisioningSupport.buildOtpAuthUri(qrCodeGenerator, label, token.getSecret());
            String qrCode = null;
            try {
                qrCode = OtpProvisioningSupport.generateQrImage(qrCodeGenerator, otpAuthUri);
            } catch (Exception e) {
                log.warn("Failed to generate provisioning QR code for token id {}", token.getId(), e);
            }
            builder.secret(token.getSecret()).otpAuthUri(otpAuthUri).qrCode(qrCode);
        }
        return builder.build();
    }
}
