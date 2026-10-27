package com.authprovider.radius;

import com.authprovider.entity.User;
import com.authprovider.service.MfaPreAuthService;
import com.authprovider.service.UserOtpService;
import com.authprovider.service.UsernameNormalizer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

import static com.authprovider.radius.RadiusConstants.*;

@Slf4j
@Component
public class RadiusAuthenticationHandler {

    private static final Pattern OTP_PATTERN = Pattern.compile("\\d{6}");
    private static final String REJECT_MESSAGE = "Authentication failed";
    private static final String PREAUTH_REQUIRED_MESSAGE = "MFA pre-authentication required";

    private final RadiusProperties properties;
    private final PrimaryCredentialVerifier credentialVerifier;
    private final UserOtpService userOtpService;
    private final RadiusChallengeStore challengeStore;
    private final RadiusAuthGuard authGuard;
    private final MfaPreAuthService mfaPreAuthService;

    public RadiusAuthenticationHandler(RadiusProperties properties,
                                       PrimaryCredentialVerifier credentialVerifier,
                                       UserOtpService userOtpService,
                                       RadiusChallengeStore challengeStore,
                                       RadiusAuthGuard authGuard) {
        this(properties, credentialVerifier, userOtpService, challengeStore, authGuard, null);
    }

    @Autowired
    public RadiusAuthenticationHandler(RadiusProperties properties,
                                       PrimaryCredentialVerifier credentialVerifier,
                                       UserOtpService userOtpService,
                                       RadiusChallengeStore challengeStore,
                                       RadiusAuthGuard authGuard,
                                       MfaPreAuthService mfaPreAuthService) {
        this.properties = properties;
        this.credentialVerifier = credentialVerifier;
        this.userOtpService = userOtpService;
        this.challengeStore = challengeStore;
        this.authGuard = authGuard;
        this.mfaPreAuthService = mfaPreAuthService;
    }

    public Optional<byte[]> handle(RadiusPacket request, InetAddress clientAddress) {
        return switch (request.getCode()) {
            case ACCESS_REQUEST -> handleAccessRequest(request, clientAddress);
            case STATUS_SERVER -> handleStatusServer(request, clientAddress);
            default -> {
                log.debug("Discarding unsupported RADIUS code {} from {}", request.getCode(), clientAddress.getHostAddress());
                yield Optional.empty();
            }
        };
    }

    private Optional<byte[]> handleStatusServer(RadiusPacket request, InetAddress clientAddress) {
        if (!RadiusCrypto.verifyRequestMessageAuthenticator(request, properties.sharedSecretBytes())) {
            log.warn("Discarding Status-Server from {} with missing or invalid Message-Authenticator", clientAddress.getHostAddress());
            return Optional.empty();
        }
        return Optional.of(respond(request, ACCESS_ACCEPT, List.of()));
    }

    private Optional<byte[]> handleAccessRequest(RadiusPacket request, InetAddress clientAddress) {
        byte[] secret = properties.sharedSecretBytes();
        String client = clientAddress.getHostAddress();
        boolean hasEap = request.countAttributes(ATTR_EAP_MESSAGE) > 0;

        if (request.hasMessageAuthenticator()) {
            if (!RadiusCrypto.verifyRequestMessageAuthenticator(request, secret)) {
                log.warn("Discarding Access-Request from {}: invalid Message-Authenticator (check shared secret)", client);
                return Optional.empty();
            }
        } else if (hasEap || properties.isRequireMessageAuthenticator()) {
            log.warn("Discarding Access-Request from {}: Message-Authenticator required but missing", client);
            return Optional.empty();
        }

        if (hasEap) {
            log.info("Rejecting EAP Access-Request from {}: EAP is not supported", client);
            return Optional.of(reject(request));
        }

        if (request.countAttributes(ATTR_CHAP_PASSWORD) != 0
                || request.countAttributes(ATTR_USER_NAME) != 1
                || request.countAttributes(ATTR_USER_PASSWORD) > 1
                || request.countAttributes(ATTR_STATE) > 1) {
            log.info("Rejecting malformed or unsupported Access-Request from {}", client);
            return Optional.of(reject(request));
        }

        String userName = request.findAttribute(ATTR_USER_NAME).orElseThrow().getValueAsString();
        if (userName.isBlank()) {
            return Optional.of(reject(request));
        }

        Optional<RadiusAttribute> passwordAttr = request.findAttribute(ATTR_USER_PASSWORD);
        Optional<RadiusAttribute> stateAttr = request.findAttribute(ATTR_STATE);

        // Out-of-Band Pre-Auth mode: User-Name without User-Password (and without State)
        if (passwordAttr.isEmpty()) {
            if (stateAttr.isPresent() || mfaPreAuthService == null) {
                return Optional.of(reject(request));
            }
            if (mfaPreAuthService.consumeApproval(userName)) {
                log.info("RADIUS Access-Accept for user '{}' from {} (MFA approval consumed)", sanitize(userName), client);
                return Optional.of(respond(request, ACCESS_ACCEPT, List.of()));
            }
            log.info("RADIUS Access-Reject for user '{}' from {} (no active MFA approval)", sanitize(userName), client);
            return Optional.of(respond(request, ACCESS_REJECT,
                    List.of(RadiusAttribute.ofString(ATTR_REPLY_MESSAGE, PREAUTH_REQUIRED_MESSAGE))));
        }

        byte[] password;
        try {
            password = RadiusCrypto.decryptUserPassword(
                    passwordAttr.get().getValue(), secret, request.getAuthenticator());
        } catch (RadiusException e) {
            log.info("Rejecting Access-Request from {}: {}", client, e.getMessage());
            return Optional.of(reject(request));
        }

        try {
            if (stateAttr.isPresent()) {
                return Optional.of(handleChallengeResponse(request, clientAddress, userName, stateAttr.get().getValue(), password));
            }
            return Optional.of(handlePrimaryAuthentication(request, clientAddress, userName, password));
        } finally {
            Arrays.fill(password, (byte) 0);
        }
    }

    private byte[] handlePrimaryAuthentication(RadiusPacket request, InetAddress clientAddress, String userName, byte[] password) {
        String client = clientAddress.getHostAddress();
        String safeUser = sanitize(userName);
        Optional<User> found = credentialVerifier.findUser(userName);
        if (found.isEmpty()) {
            credentialVerifier.simulatePasswordCheck(password);
            log.info("RADIUS primary authentication failed for unknown user '{}' from {}", safeUser, client);
            return reject(request);
        }
        User user = found.get();
        if (authGuard.isLocked(user.getId())) {
            credentialVerifier.simulatePasswordCheck(password);
            log.warn("RADIUS authentication refused for locked-out user '{}' from {}", safeUser, client);
            return reject(request);
        }
        if (!credentialVerifier.passwordMatches(user, password)) {
            authGuard.recordFailure(user.getId());
            log.info("RADIUS primary authentication failed for user '{}' from {}", safeUser, client);
            return reject(request);
        }
        if (user.getSecret() == null || user.getSecret().isEmpty()) {
            log.warn("RADIUS authentication refused for user '{}': no OTP secret enrolled", safeUser);
            return reject(request);
        }
        Optional<byte[]> state = challengeStore.create(user.getId(), userName, clientAddress);
        if (state.isEmpty()) {
            log.error("RADIUS challenge capacity exhausted; rejecting user '{}' from {}", safeUser, client);
            return reject(request);
        }
        log.info("RADIUS primary authentication succeeded for user '{}' from {}; issuing OTP challenge", safeUser, client);
        List<RadiusAttribute> attributes = new ArrayList<>();
        attributes.add(RadiusAttribute.ofString(ATTR_REPLY_MESSAGE, properties.getChallenge().getPrompt()));
        attributes.add(new RadiusAttribute(ATTR_STATE, state.get()));
        attributes.add(RadiusAttribute.ofInteger(ATTR_SESSION_TIMEOUT, properties.getChallenge().getTtlSeconds()));
        return respond(request, ACCESS_CHALLENGE, attributes);
    }

    private byte[] handleChallengeResponse(RadiusPacket request, InetAddress clientAddress, String userName,
                                           byte[] state, byte[] password) {
        String client = clientAddress.getHostAddress();
        String safeUser = sanitize(userName);
        Optional<RadiusChallengeStore.ChallengeSession> consumed = challengeStore.consume(state);
        if (consumed.isEmpty()) {
            log.info("RADIUS challenge response from {} for user '{}' has unknown, expired or reused State", client, safeUser);
            return reject(request);
        }
        RadiusChallengeStore.ChallengeSession session = consumed.get();
        if (!session.clientAddress().equals(clientAddress) || !sameUser(session.userName(), userName)) {
            log.warn("RADIUS challenge response from {} for user '{}' does not match the issued challenge", client, safeUser);
            return reject(request);
        }
        if (authGuard.isLocked(session.userId())) {
            log.warn("RADIUS authentication refused for locked-out user '{}' from {}", safeUser, client);
            return reject(request);
        }
        String otp = new String(password, StandardCharsets.UTF_8).trim();
        if (!OTP_PATTERN.matcher(otp).matches()) {
            authGuard.recordFailure(session.userId());
            log.info("RADIUS OTP verification failed for user '{}' from {}: malformed passcode", safeUser, client);
            return reject(request);
        }
        boolean valid = userOtpService.validateUserOtp(session.userId(), Integer.parseInt(otp)).orElse(false);
        if (!valid) {
            authGuard.recordFailure(session.userId());
            log.info("RADIUS OTP verification failed for user '{}' from {}", safeUser, client);
            return reject(request);
        }
        if (!authGuard.markOtpUsed(session.userId(), otp)) {
            authGuard.recordFailure(session.userId());
            log.warn("RADIUS OTP replay detected for user '{}' from {}", safeUser, client);
            return reject(request);
        }
        authGuard.recordSuccess(session.userId());
        log.info("RADIUS authentication succeeded for user '{}' from {}", safeUser, client);
        return respond(request, ACCESS_ACCEPT, List.of());
    }

    private boolean sameUser(String sessionUser, String requestUser) {
        if (sessionUser.equalsIgnoreCase(requestUser)) {
            return true;
        }
        if (properties.isStripRealm()) {
            String normSession = UsernameNormalizer.normalize(sessionUser);
            String normRequest = UsernameNormalizer.normalize(requestUser);
            return normSession != null && normSession.equals(normRequest);
        }
        return false;
    }

    private byte[] reject(RadiusPacket request) {
        return respond(request, ACCESS_REJECT, List.of(RadiusAttribute.ofString(ATTR_REPLY_MESSAGE, REJECT_MESSAGE)));
    }

    private byte[] respond(RadiusPacket request, int code, List<RadiusAttribute> attributes) {
        List<RadiusAttribute> all = new ArrayList<>(attributes);
        all.addAll(request.getAttributes(ATTR_PROXY_STATE));
        return RadiusCrypto.buildResponse(code, request.getIdentifier(), request.getAuthenticator(), all,
                properties.sharedSecretBytes());
    }

    static String sanitize(String value) {
        StringBuilder sb = new StringBuilder(Math.min(value.length(), 128));
        for (int i = 0; i < value.length() && i < 128; i++) {
            char c = value.charAt(i);
            sb.append(Character.isISOControl(c) ? '?' : c);
        }
        return sb.toString();
    }
}
