package com.authprovider.radius;

import com.authprovider.entity.AuthAuditLog;
import com.authprovider.entity.User;
import com.authprovider.service.AuthAuditService;
import com.authprovider.service.MfaPreAuthService;
import com.authprovider.service.SecurityPolicyService;
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
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;

import static com.authprovider.radius.RadiusConstants.*;

@Slf4j
@Component
public class RadiusAuthenticationHandler {

    private static final Pattern OTP_PATTERN = Pattern.compile("\\d{6}");
    private static final String REJECT_MESSAGE = "Authentication failed";
    private static final String OUT_OF_BAND_REJECT_MESSAGE = "MFA pre-authentication required";
    private static final String NOT_ENROLLED_REJECT_MESSAGE = "MFA enrollment required";

    private final RadiusProperties properties;
    private final PrimaryCredentialVerifier credentialVerifier;
    private final UserOtpService userOtpService;
    private final RadiusChallengeStore challengeStore;
    private final RadiusAuthGuard authGuard;
    private final MfaPreAuthService mfaPreAuthService;
    private final RadiusClientRegistry clientRegistry;
    private final SecurityPolicyService policyService;
    private final AuthAuditService auditService;

    /** Per-request context: the sending client and its shared secret. */
    private record RequestContext(InetAddress address, String clientName, byte[] secret) {
        String host() {
            return address == null ? "unknown" : address.getHostAddress();
        }
    }

    public RadiusAuthenticationHandler(RadiusProperties properties,
                                       PrimaryCredentialVerifier credentialVerifier,
                                       UserOtpService userOtpService,
                                       RadiusChallengeStore challengeStore,
                                       RadiusAuthGuard authGuard) {
        this(properties, credentialVerifier, userOtpService, challengeStore, authGuard, null);
    }

    public RadiusAuthenticationHandler(RadiusProperties properties,
                                       PrimaryCredentialVerifier credentialVerifier,
                                       UserOtpService userOtpService,
                                       RadiusChallengeStore challengeStore,
                                       RadiusAuthGuard authGuard,
                                       MfaPreAuthService mfaPreAuthService) {
        this(properties, credentialVerifier, userOtpService, challengeStore, authGuard, mfaPreAuthService,
                new RadiusClientRegistry(properties), SecurityPolicyService.fromProperties(properties),
                AuthAuditService.noOp());
    }

    @Autowired
    public RadiusAuthenticationHandler(RadiusProperties properties,
                                       PrimaryCredentialVerifier credentialVerifier,
                                       UserOtpService userOtpService,
                                       RadiusChallengeStore challengeStore,
                                       RadiusAuthGuard authGuard,
                                       MfaPreAuthService mfaPreAuthService,
                                       RadiusClientRegistry clientRegistry,
                                       SecurityPolicyService policyService,
                                       AuthAuditService auditService) {
        this.properties = properties;
        this.credentialVerifier = credentialVerifier;
        this.userOtpService = userOtpService;
        this.challengeStore = challengeStore;
        this.authGuard = authGuard;
        this.mfaPreAuthService = mfaPreAuthService;
        this.clientRegistry = clientRegistry;
        this.policyService = policyService;
        this.auditService = auditService == null ? AuthAuditService.noOp() : auditService;
        if (challengeStore != null && !challengeStore.isPersistent() && authGuard != null
                && authGuard.getLockoutService() != null) {
            // Node-local challenges are discarded by this node when the account is locked out.
            authGuard.getLockoutService().sessionInvalidator().addListener(challengeStore::invalidateUser);
        }
    }

    RadiusClientRegistry getClientRegistry() {
        return clientRegistry;
    }

    /**
     * Handles a request, resolving the client's shared secret from its address. Requests from
     * unknown clients are silently discarded.
     */
    public Optional<byte[]> handle(RadiusPacket request, InetAddress clientAddress) {
        Optional<RadiusClientRegistry.ResolvedClient> client = clientRegistry.resolve(clientAddress);
        if (client.isEmpty()) {
            log.warn("Dropping RADIUS packet from unauthorized client {}",
                    clientAddress == null ? "null" : clientAddress.getHostAddress());
            return Optional.empty();
        }
        return handle(request, clientAddress, client.get());
    }

    /** Handles a request from an already resolved client. */
    public Optional<byte[]> handle(RadiusPacket request, InetAddress clientAddress, RadiusClientRegistry.ResolvedClient client) {
        RequestContext context = new RequestContext(clientAddress, client.name(), client.secret());
        return switch (request.getCode()) {
            case ACCESS_REQUEST -> handleAccessRequest(request, context);
            case STATUS_SERVER -> handleStatusServer(request, context);
            default -> {
                log.debug("Discarding unsupported RADIUS code {} from {}", request.getCode(), context.host());
                yield Optional.empty();
            }
        };
    }

    private Optional<byte[]> handleStatusServer(RadiusPacket request, RequestContext context) {
        if (!RadiusCrypto.verifyRequestMessageAuthenticator(request, context.secret())) {
            log.warn("Discarding Status-Server from {} with missing or invalid Message-Authenticator", context.host());
            return Optional.empty();
        }
        return Optional.of(respond(request, context, ACCESS_ACCEPT, List.of()));
    }

    private Optional<byte[]> handleAccessRequest(RadiusPacket request, RequestContext context) {
        byte[] secret = context.secret();
        String client = context.host();
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

        String rawUserName = request.findAttribute(ATTR_USER_NAME).map(RadiusAttribute::getValueAsString).orElse(null);

        if (hasEap) {
            log.info("Rejecting EAP Access-Request from {}: EAP is not supported", client);
            audit(context, rawUserName, null, AuthAuditLog.Outcome.FAILURE, "EAP_NOT_SUPPORTED", null);
            return Optional.of(reject(request, context));
        }

        if (request.countAttributes(ATTR_CHAP_PASSWORD) != 0
                || request.countAttributes(ATTR_USER_NAME) != 1
                || request.countAttributes(ATTR_USER_PASSWORD) > 1
                || request.countAttributes(ATTR_STATE) > 1) {
            log.info("Rejecting malformed or unsupported Access-Request from {}", client);
            audit(context, rawUserName, null, AuthAuditLog.Outcome.FAILURE, "MALFORMED_REQUEST", null);
            return Optional.of(reject(request, context));
        }

        String userName = request.findAttribute(ATTR_USER_NAME).orElseThrow().getValueAsString();
        if (userName.isBlank()) {
            audit(context, userName, null, AuthAuditLog.Outcome.FAILURE, "MALFORMED_REQUEST", null);
            return Optional.of(reject(request, context));
        }

        Optional<RadiusAttribute> passwordAttr = request.findAttribute(ATTR_USER_PASSWORD);
        Optional<RadiusAttribute> stateAttr = request.findAttribute(ATTR_STATE);

        if (passwordAttr.isEmpty()) {
            if (stateAttr.isPresent()) {
                log.info("Rejecting Access-Request from {}: State without User-Password", client);
                audit(context, userName, null, AuthAuditLog.Outcome.FAILURE, "MALFORMED_REQUEST", null);
                return Optional.of(reject(request, context));
            }
            return Optional.of(handleOutOfBandApproval(request, context, userName));
        }

        byte[] password;
        try {
            password = RadiusCrypto.decryptUserPassword(
                    passwordAttr.get().getValue(), secret, request.getAuthenticator());
        } catch (RadiusException e) {
            log.info("Rejecting Access-Request from {}: {}", client, e.getMessage());
            audit(context, userName, null, AuthAuditLog.Outcome.FAILURE, "MALFORMED_PASSWORD", null);
            return Optional.of(reject(request, context));
        }

        try {
            if (stateAttr.isPresent()) {
                return Optional.of(handleChallengeResponse(request, context, userName, stateAttr.get().getValue(), password));
            }
            return Optional.of(handlePrimaryAuthentication(request, context, userName, password));
        } finally {
            Arrays.fill(password, (byte) 0);
        }
    }

    private byte[] handleOutOfBandApproval(RadiusPacket request, RequestContext context, String userName) {
        String client = context.host();
        String safeUser = sanitize(userName);
        if (mfaPreAuthService == null || properties.getMfa() == null || !properties.getMfa().isOutOfBandEnabled()) {
            log.info("RADIUS Access-Reject for user '{}' from {} (User-Password required; out-of-band MFA disabled)",
                    safeUser, client);
            audit(context, userName, null, AuthAuditLog.Outcome.FAILURE, "OUT_OF_BAND_DISABLED", null);
            return reject(request, context);
        }
        // Resolve the RADIUS identity to the canonical local account (same rules as every other channel).
        Optional<User> account = credentialVerifier.findUser(userName);
        if (account.isEmpty() || account.get().getId() == null) {
            log.info("RADIUS Access-Reject for user '{}' from {} (unknown account; no MFA approval)", safeUser, client);
            audit(context, userName, null, AuthAuditLog.Outcome.FAILURE, "NO_MFA_APPROVAL", null);
            return respond(request, context, ACCESS_REJECT,
                    List.of(RadiusAttribute.ofString(ATTR_REPLY_MESSAGE, OUT_OF_BAND_REJECT_MESSAGE)));
        }
        Long userId = account.get().getId();
        if (authGuard.isLocked(userId)) {
            log.warn("RADIUS authentication refused for locked-out user '{}' from {}", safeUser, client);
            audit(context, userName, userId, AuthAuditLog.Outcome.LOCKED, "LOCKED_OUT", null);
            return reject(request, context);
        }
        if (mfaPreAuthService.consumeApproval(userName, userId)) {
            authGuard.recordSuccess(userId);
            log.info("RADIUS Access-Accept for user '{}' from {} (MFA approval consumed)", safeUser, client);
            audit(context, userName, userId, AuthAuditLog.Outcome.SUCCESS, "MFA_APPROVAL_CONSUMED", null);
            return respond(request, context, ACCESS_ACCEPT, List.of());
        }
        // An unapproved out-of-band request is a failed authentication of the account.
        authGuard.recordFailure(userId);
        log.info("RADIUS Access-Reject for user '{}' from {} (no active MFA approval)", safeUser, client);
        audit(context, userName, userId, AuthAuditLog.Outcome.FAILURE, "NO_MFA_APPROVAL", null);
        return respond(request, context, ACCESS_REJECT,
                List.of(RadiusAttribute.ofString(ATTR_REPLY_MESSAGE, OUT_OF_BAND_REJECT_MESSAGE)));
    }

    private byte[] handlePrimaryAuthentication(RadiusPacket request, RequestContext context, String userName, byte[] password) {
        String client = context.host();
        String safeUser = sanitize(userName);
        PrimaryCredentialVerifier.Verification verification =
                credentialVerifier.verify(userName, password, authGuard::isLocked);
        User user = verification.user();
        Long userId = user == null ? null : user.getId();
        switch (verification.outcome()) {
            case AUTHENTICATED:
                break;
            case UNKNOWN_USER:
                log.info("RADIUS primary authentication failed for unknown user '{}' from {} ({})",
                        safeUser, client, verification.source());
                audit(context, userName, null, AuthAuditLog.Outcome.FAILURE, "UNKNOWN_USER", verification.source());
                return reject(request, context);
            case LOCKED:
                log.warn("RADIUS authentication refused for locked-out user '{}' from {}", safeUser, client);
                audit(context, userName, userId, AuthAuditLog.Outcome.LOCKED, "LOCKED_OUT", verification.source());
                return reject(request, context);
            case NOT_ENROLLED:
                log.warn("RADIUS authentication refused for user '{}' ({}): no OTP secret enrolled",
                        safeUser, verification.source());
                audit(context, userName, userId, AuthAuditLog.Outcome.FAILURE, "NOT_ENROLLED", verification.source());
                return respond(request, context, ACCESS_REJECT,
                        List.of(RadiusAttribute.ofString(ATTR_REPLY_MESSAGE, NOT_ENROLLED_REJECT_MESSAGE)));
            case DIRECTORY_UNAVAILABLE:
                log.error("RADIUS authentication for user '{}' from {} failed: directory service unavailable",
                        safeUser, client);
                audit(context, userName, null, AuthAuditLog.Outcome.ERROR, "DIRECTORY_UNAVAILABLE", verification.source());
                return reject(request, context);
            case INVALID_CREDENTIALS:
            default:
                if (userId != null) {
                    authGuard.recordFailure(userId);
                }
                log.info("RADIUS primary authentication failed for user '{}' from {} ({})",
                        safeUser, client, verification.source());
                audit(context, userName, userId, AuthAuditLog.Outcome.FAILURE, "INVALID_CREDENTIALS", verification.source());
                return reject(request, context);
        }
        log.debug("RADIUS primary credentials for user '{}' verified against {}", safeUser, verification.source());
        Optional<byte[]> state = challengeStore.create(userId, userName, context.address());
        if (state.isEmpty()) {
            log.error("RADIUS challenge capacity exhausted; rejecting user '{}' from {}", safeUser, client);
            audit(context, userName, userId, AuthAuditLog.Outcome.ERROR, "CHALLENGE_CAPACITY_EXHAUSTED", verification.source());
            return reject(request, context);
        }
        log.info("RADIUS primary authentication succeeded for user '{}' from {}; issuing OTP challenge", safeUser, client);
        audit(context, userName, userId, AuthAuditLog.Outcome.CHALLENGE, "OTP_CHALLENGE_ISSUED", verification.source());
        List<RadiusAttribute> attributes = new ArrayList<>();
        attributes.add(RadiusAttribute.ofString(ATTR_REPLY_MESSAGE, properties.getChallenge().getPrompt()));
        attributes.add(new RadiusAttribute(ATTR_STATE, state.get()));
        attributes.add(RadiusAttribute.ofInteger(ATTR_SESSION_TIMEOUT, policyService.current().getChallengeTtlSeconds()));
        return respond(request, context, ACCESS_CHALLENGE, attributes);
    }

    private byte[] handleChallengeResponse(RadiusPacket request, RequestContext context, String userName,
                                           byte[] state, byte[] password) {
        String client = context.host();
        String safeUser = sanitize(userName);
        // Inspect the session without consuming it: a request from another client or for another user must
        // not destroy the legitimate user's pending challenge.
        Optional<RadiusChallengeStore.ChallengeSession> pending = challengeStore.peek(state);
        if (pending.isEmpty()) {
            log.info("RADIUS challenge response from {} for user '{}' has unknown, expired or reused State", client, safeUser);
            audit(context, userName, null, AuthAuditLog.Outcome.FAILURE, "INVALID_STATE", null);
            return reject(request, context);
        }
        RadiusChallengeStore.ChallengeSession session = pending.get();
        Long userId = session.userId();
        if (!Objects.equals(session.clientAddress(), context.address()) || !matchesChallengeUser(session, userName)) {
            log.warn("RADIUS challenge response from {} for user '{}' does not match the issued challenge", client, safeUser);
            audit(context, userName, null, AuthAuditLog.Outcome.FAILURE, "CHALLENGE_MISMATCH", null);
            return reject(request, context);
        }
        Optional<RadiusChallengeStore.ChallengeSession> consumed = challengeStore.consume(state);
        if (consumed.isEmpty() || !Objects.equals(consumed.get().userId(), userId)) {
            log.info("RADIUS challenge response from {} for user '{}' has unknown, expired or reused State", client, safeUser);
            audit(context, userName, null, AuthAuditLog.Outcome.FAILURE, "INVALID_STATE", null);
            return reject(request, context);
        }
        if (authGuard.isLocked(userId)) {
            log.warn("RADIUS authentication refused for locked-out user '{}' from {}", safeUser, client);
            audit(context, userName, userId, AuthAuditLog.Outcome.LOCKED, "LOCKED_OUT", null);
            return reject(request, context);
        }
        String otp = new String(password, StandardCharsets.UTF_8).trim();
        if (!OTP_PATTERN.matcher(otp).matches()) {
            authGuard.recordFailure(userId);
            log.info("RADIUS OTP verification failed for user '{}' from {}: malformed passcode", safeUser, client);
            audit(context, userName, userId, AuthAuditLog.Outcome.FAILURE, "MALFORMED_OTP", null);
            return reject(request, context);
        }
        // When the OTP service enforces the shared account protections itself (lockout reservation,
        // failure accounting, single-use time steps, clearing on success) the outcome is not recorded twice.
        boolean selfAccounting = userOtpService.enforcesAccountProtection();
        boolean valid = userOtpService.validateUserOtp(userId, Integer.parseInt(otp)).orElse(false);
        if (!valid) {
            if (!selfAccounting) {
                authGuard.recordFailure(userId);
            }
            log.info("RADIUS OTP verification failed for user '{}' from {}", safeUser, client);
            audit(context, userName, userId, AuthAuditLog.Outcome.FAILURE, "INVALID_OTP", null);
            return reject(request, context);
        }
        if (!selfAccounting && !authGuard.markOtpUsed(userId, otp)) {
            authGuard.recordFailure(userId);
            log.warn("RADIUS OTP replay detected for user '{}' from {}", safeUser, client);
            audit(context, userName, userId, AuthAuditLog.Outcome.FAILURE, "OTP_REPLAY", null);
            return reject(request, context);
        }
        authGuard.recordSuccess(userId);
        log.info("RADIUS authentication succeeded for user '{}' from {}", safeUser, client);
        audit(context, userName, userId, AuthAuditLog.Outcome.SUCCESS, "AUTHENTICATED", null);
        return respond(request, context, ACCESS_ACCEPT, List.of());
    }

    private boolean matchesChallengeUser(RadiusChallengeStore.ChallengeSession session, String requestUser) {
        if (credentialVerifier != null && session.userId() != null) {
            Optional<User> resolved = credentialVerifier.findUser(requestUser);
            if (resolved.isPresent()) {
                return Objects.equals(resolved.get().getId(), session.userId());
            }
        }
        return sameUser(session.userName(), requestUser);
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

    private void audit(RequestContext context, String userName, Long userId, AuthAuditLog.Outcome outcome,
                       String reason, String source) {
        auditService.record(AuthAuditLog.Channel.RADIUS, userName, userId, context.host(), context.clientName(),
                outcome, reason, source);
    }

    private byte[] reject(RadiusPacket request, RequestContext context) {
        return respond(request, context, ACCESS_REJECT,
                List.of(RadiusAttribute.ofString(ATTR_REPLY_MESSAGE, REJECT_MESSAGE)));
    }

    private byte[] respond(RadiusPacket request, RequestContext context, int code, List<RadiusAttribute> attributes) {
        List<RadiusAttribute> all = new ArrayList<>(attributes);
        all.addAll(request.getAttributes(ATTR_PROXY_STATE));
        return RadiusCrypto.buildResponse(code, request.getIdentifier(), request.getAuthenticator(), all,
                context.secret());
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
