package com.authprovider.radius;

import com.authprovider.entity.AuthAuditLog;
import com.authprovider.entity.AuthFailureRecord;
import com.authprovider.entity.LdapDirectory;
import com.authprovider.entity.MfaApproval;
import com.authprovider.entity.RadiusClient;
import com.authprovider.entity.SecurityPolicy;
import com.authprovider.entity.User;
import com.authprovider.repository.AuthAuditLogRepository;
import com.authprovider.repository.AuthFailureRecordRepository;
import com.authprovider.repository.LdapDirectoryRepository;
import com.authprovider.repository.MfaApprovalRepository;
import com.authprovider.repository.RadiusChallengeSessionRepository;
import com.authprovider.repository.RadiusClientRepository;
import com.authprovider.repository.SecurityPolicyRepository;
import com.authprovider.repository.UserRepository;
import com.authprovider.service.AuthAuditService;
import com.authprovider.service.AuthFailureStore;
import com.authprovider.service.MfaPreAuthServiceImpl;
import com.authprovider.service.OtpVerificationService;
import com.authprovider.service.SecurityPolicyService;
import com.authprovider.service.TotpService;
import com.authprovider.service.UserService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.PlatformTransactionManager;

import java.time.Clock;
import java.util.List;
import java.util.Optional;

import static com.authprovider.radius.RadiusConstants.*;
import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(properties = {
        "radius.port=0",
        "radius.bind-address=127.0.0.1",
        "iam.bootstrap.radius.shared-secret=persist-secret",
        "iam.bootstrap.policy.challenge-ttl-seconds=33",
        "iam.bootstrap.policy.max-failures=3",
        "iam.bootstrap.policy.lockout-seconds=120",
        "iam.bootstrap.policy.mfa-approval-ttl-seconds=42"
})
class PersistentRadiusStateIntegrationTest {

    private static final String PASSWORD = "Str0ng!Pass";
    private static final String SECRET = "JBSWY3DPEHPK3PXP";

    @Autowired private RadiusServer radiusServer;
    @Autowired private UserRepository userRepository;
    @Autowired private TotpService totpService;
    @Autowired private UserService userService;
    @Autowired private RadiusClientRepository clientRepository;
    @Autowired private LdapDirectoryRepository directoryRepository;
    @Autowired private SecurityPolicyRepository policyRepository;
    @Autowired private RadiusChallengeSessionRepository challengeRepository;
    @Autowired private AuthFailureRecordRepository failureRepository;
    @Autowired private MfaApprovalRepository approvalRepository;
    @Autowired private AuthAuditLogRepository auditRepository;
    @Autowired private SecurityPolicyService policyService;
    @Autowired private AuthFailureStore failureStore;
    @Autowired private AuthAuditService auditService;
    @Autowired private OtpVerificationService otpVerificationService;
    @Autowired private PlatformTransactionManager transactionManager;
    @Autowired private Clock clock;
    @Autowired private com.authprovider.service.LoginService loginService;

    private User user;

    @BeforeEach
    void setUp() {
        challengeRepository.deleteAll();
        failureRepository.deleteAll();
        approvalRepository.deleteAll();
        userRepository.deleteAll();
        user = userRepository.save(User.builder().username("persist-user").password(PASSWORD).secret(SECRET).build());
    }

    @AfterEach
    void tearDown() {
        clientRepository.findAll().stream()
                .filter(c -> !c.getName().startsWith("default"))
                .forEach(clientRepository::delete);
        SecurityPolicy policy = policyRepository.findByName(SecurityPolicy.DEFAULT_NAME).orElseThrow();
        policy.setMaxFailures(3);
        policyRepository.save(policy);
    }

    @Test
    void defaultsAreSeededFromConfigurationProperties() {
        SecurityPolicy policy = policyRepository.findByName(SecurityPolicy.DEFAULT_NAME).orElseThrow();
        assertEquals(3, policy.getMaxFailures());
        assertEquals(120, policy.getLockoutSeconds());
        assertEquals(33, policy.getChallengeTtlSeconds());
        assertEquals(42, policy.getMfaApprovalTtlSeconds());

        List<RadiusClient> clients = clientRepository.findAll();
        assertTrue(clients.stream().anyMatch(c -> "0.0.0.0/0".equals(c.getAddress())
                && "persist-secret".equals(c.getSharedSecret()) && c.isActive()));

        List<LdapDirectory> directories = directoryRepository.findAll();
        assertEquals(0, directories.size());
    }

    @Test
    void challengeSessionIsPersistedAndSingleUse() throws Exception {
        try (RadiusTestClient client = new RadiusTestClient(radiusServer.getLocalPort(), "persist-secret")) {
            RadiusPacket challenge = client.sendExpectingResponse(client.accessRequest("persist-user", PASSWORD, null));
            assertEquals(ACCESS_CHALLENGE, challenge.getCode());
            assertEquals(33, challenge.getAttribute(ATTR_SESSION_TIMEOUT).orElseThrow().getValueAsInteger());
            assertEquals(1, challengeRepository.count());
            byte[] state = challenge.getAttribute(ATTR_STATE).orElseThrow().getValue();

            String otp = String.format("%06d", totpService.generateOtp(SECRET));
            assertEquals(ACCESS_ACCEPT, client.sendExpectingResponse(client.accessRequest("persist-user", otp, state)).getCode());
            assertEquals(0, challengeRepository.count());
            assertEquals(ACCESS_REJECT, client.sendExpectingResponse(client.accessRequest("persist-user", otp, state)).getCode());
        }
        List<AuthAuditLog> audit = auditRepository.findByUsernameOrderByIdAsc("persist-user");
        assertTrue(audit.stream().anyMatch(a -> a.getOutcome() == AuthAuditLog.Outcome.CHALLENGE));
        assertTrue(audit.stream().anyMatch(a -> a.getOutcome() == AuthAuditLog.Outcome.SUCCESS
                && a.getChannel() == AuthAuditLog.Channel.RADIUS && "default".equals(a.getClientName())));
        assertTrue(audit.stream().anyMatch(a -> "INVALID_STATE".equals(a.getReason())));
    }

    @Test
    void dedicatedClientSecretIsResolvedFromSenderAddress() throws Exception {
        clientRepository.save(RadiusClient.builder().name("loopback-subnet").address("127.0.0.0/8")
                .sharedSecret("subnet-secret").active(true).build());
        try (RadiusTestClient subnet = new RadiusTestClient(radiusServer.getLocalPort(), "subnet-secret");
             RadiusTestClient legacy = new RadiusTestClient(radiusServer.getLocalPort(), "persist-secret")) {
            assertEquals(ACCESS_CHALLENGE,
                    subnet.sendExpectingResponse(subnet.accessRequest("persist-user", PASSWORD, null)).getCode());
            // The global secret no longer validates packets from this (more specific) subnet.
            assertTrue(legacy.send(legacy.accessRequest("persist-user", PASSWORD, null)).isEmpty());

            clientRepository.save(RadiusClient.builder().name("loopback-host").address("127.0.0.1")
                    .sharedSecret("host-secret").active(false).build());
            // Inactive clients are ignored.
            assertEquals(ACCESS_CHALLENGE,
                    subnet.sendExpectingResponse(subnet.accessRequest("persist-user", PASSWORD, null)).getCode());

            RadiusClient host = clientRepository.findByName("loopback-host").orElseThrow();
            host.setActive(true);
            clientRepository.save(host);
            try (RadiusTestClient hostClient = new RadiusTestClient(radiusServer.getLocalPort(), "host-secret")) {
                assertEquals(ACCESS_CHALLENGE,
                        hostClient.sendExpectingResponse(hostClient.accessRequest("persist-user", PASSWORD, null)).getCode());
            }
        }
    }

    @Test
    void unknownClientIsDropped() throws Exception {
        clientRepository.findAll().forEach(c -> {
            c.setActive(false);
            clientRepository.save(c);
        });
        try (RadiusTestClient client = new RadiusTestClient(radiusServer.getLocalPort(), "persist-secret")) {
            assertTrue(client.send(client.accessRequest("persist-user", PASSWORD, null)).isEmpty());
        } finally {
            clientRepository.findAll().forEach(c -> {
                c.setActive(true);
                clientRepository.save(c);
            });
        }
    }

    @Test
    void lockoutIsPersistedAndSurvivesRestart() throws Exception {
        try (RadiusTestClient client = new RadiusTestClient(radiusServer.getLocalPort(), "persist-secret")) {
            for (int i = 0; i < 3; i++) {
                assertEquals(ACCESS_REJECT,
                        client.sendExpectingResponse(client.accessRequest("persist-user", "wrong", null)).getCode());
            }
            AuthFailureRecord record = failureRepository
                    .findByScopeAndSubject(AuthFailureRecord.SCOPE_RADIUS, String.valueOf(user.getId())).orElseThrow();
            assertEquals(3, record.getFailureCount());
            assertNotNull(record.getLockedUntil());

            // Locked even with the right password.
            assertEquals(ACCESS_REJECT,
                    client.sendExpectingResponse(client.accessRequest("persist-user", PASSWORD, null)).getCode());
        }
        // A freshly created guard (another node / after restart) sees the same lockout.
        RadiusAuthGuard otherNode = new RadiusAuthGuard(policyService, failureStore, clock);
        assertTrue(otherNode.isLocked(user.getId()));
        assertTrue(auditRepository.findByUsernameOrderByIdAsc("persist-user").stream()
                .anyMatch(a -> a.getOutcome() == AuthAuditLog.Outcome.LOCKED));
    }

    @Test
    void policyChangesTakeEffectAtRuntime() throws Exception {
        SecurityPolicy policy = policyRepository.findByName(SecurityPolicy.DEFAULT_NAME).orElseThrow();
        policy.setMaxFailures(1);
        policyRepository.save(policy);
        try (RadiusTestClient client = new RadiusTestClient(radiusServer.getLocalPort(), "persist-secret")) {
            client.sendExpectingResponse(client.accessRequest("persist-user", "wrong", null));
            assertEquals(ACCESS_REJECT,
                    client.sendExpectingResponse(client.accessRequest("persist-user", PASSWORD, null)).getCode());
        }
    }

    @Test
    void mfaApprovalIsPersistedAndConsumableByAnotherNode() {
        MfaPreAuthServiceImpl nodeA = new MfaPreAuthServiceImpl(userService, clock, policyService,
                failureStore, approvalRepository, transactionManager, auditService, otpVerificationService);
        MfaPreAuthServiceImpl nodeB = new MfaPreAuthServiceImpl(userService, clock, policyService,
                failureStore, approvalRepository, transactionManager, auditService, otpVerificationService);

        assertTrue(nodeA.preAuthenticate("persist-user", totpService.generateOtp(SECRET)));
        Optional<MfaApproval> stored = approvalRepository.findByUsername("persist-user");
        assertTrue(stored.isPresent());
        assertEquals(42, stored.get().getExpiresAt().getEpochSecond() - stored.get().getCreatedAt().getEpochSecond());

        assertTrue(nodeB.hasActiveApproval("CORP\\persist-user"));
        assertTrue(nodeB.consumeApproval("persist-user"));
        assertFalse(nodeA.consumeApproval("persist-user"));
        assertEquals(0, approvalRepository.count());
    }

    @Test
    void mfaFailuresAreTrackedPersistently() {
        MfaPreAuthServiceImpl service = new MfaPreAuthServiceImpl(userService, clock, policyService,
                failureStore, approvalRepository, transactionManager, auditService, otpVerificationService);
        int valid = totpService.generateOtp(SECRET);
        int wrong = (valid + 1) % 1_000_000;
        for (int i = 0; i < 5; i++) {
            assertFalse(service.preAuthenticate("persist-user", wrong));
        }
        assertEquals(5, failureRepository.findByScopeAndSubject(AuthFailureRecord.SCOPE_MFA_PREAUTH, "persist-user")
                .orElseThrow().getFailureCount());
        MfaPreAuthServiceImpl restarted = new MfaPreAuthServiceImpl(userService, clock, policyService,
                failureStore, approvalRepository, transactionManager, auditService, otpVerificationService);
        assertFalse(restarted.preAuthenticate("persist-user", valid));
        assertTrue(auditRepository.findByChannelOrderByIdAsc(AuthAuditLog.Channel.MFA_PREAUTH).stream()
                .anyMatch(a -> "LOCKED_OUT".equals(a.getReason())));
    }

    @Test
    void webLoginAttemptsAreAudited() {
        loginService.login(com.authprovider.dto.LoginRequest.builder()
                .username("persist-user").password("wrong").build());
        loginService.login(com.authprovider.dto.LoginRequest.builder()
                .username("persist-user").password(PASSWORD).otp(String.format("%06d", totpService.generateOtp(SECRET))).build());
        List<AuthAuditLog> web = auditRepository.findByChannelOrderByIdAsc(AuthAuditLog.Channel.WEB_LOGIN).stream()
                .filter(a -> "persist-user".equals(a.getUsername())).toList();
        assertTrue(web.stream().anyMatch(a -> a.getOutcome() == AuthAuditLog.Outcome.FAILURE
                && "INVALID_CREDENTIALS".equals(a.getReason())));
        assertTrue(web.stream().anyMatch(a -> a.getOutcome() == AuthAuditLog.Outcome.SUCCESS
                && "LOCAL".equals(a.getSource()) && user.getId().equals(a.getUserId())));
    }

    @Test
    void auditLogIsAppendOnly() {
        auditService.record(AuthAuditLog.Channel.WEB_LOGIN, "audit-user", null, null, null,
                AuthAuditLog.Outcome.FAILURE, "INVALID_CREDENTIALS", "LOCAL");
        AuthAuditLog entry = auditRepository.findByUsernameOrderByIdAsc("audit-user").get(0);
        assertNotNull(entry.getOccurredAt());
        assertThrows(Exception.class, () -> auditRepository.delete(entry));
        assertEquals(1, auditRepository.findByUsernameOrderByIdAsc("audit-user").size());
    }
}
