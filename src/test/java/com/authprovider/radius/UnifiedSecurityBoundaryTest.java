package com.authprovider.radius;

import com.authprovider.dto.LoginRequest;
import com.authprovider.dto.LoginResponse;
import com.authprovider.entity.AuthFailureRecord;
import com.authprovider.entity.SecurityPolicy;
import com.authprovider.entity.User;
import com.authprovider.repository.AuthFailureRecordRepository;
import com.authprovider.repository.MfaApprovalRepository;
import com.authprovider.repository.RadiusChallengeSessionRepository;
import com.authprovider.repository.SecurityPolicyRepository;
import com.authprovider.repository.UserRepository;
import com.authprovider.service.AccountLockoutService;
import com.authprovider.service.AuthAuditService;
import com.authprovider.service.AuthFailureStore;
import com.authprovider.service.HmacOtpProcessor;
import com.authprovider.service.LoginService;
import com.authprovider.service.MfaPreAuthService;
import com.authprovider.service.MfaPreAuthServiceImpl;
import com.authprovider.service.OcraService;
import com.authprovider.service.OtpVerificationService;
import com.authprovider.service.SecurityPolicyService;
import com.authprovider.service.TotpService;
import com.authprovider.service.TotpServiceImpl;
import com.authprovider.service.UserOtpService;
import com.authprovider.service.UserService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.PlatformTransactionManager;

import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static com.authprovider.radius.RadiusConstants.*;
import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(properties = {
        "radius.port=0",
        "radius.bind-address=127.0.0.1",
        "iam.bootstrap.radius.shared-secret=unified-secret",
        "iam.bootstrap.policy.max-failures=3",
        "iam.bootstrap.policy.lockout-seconds=120"
})
class UnifiedSecurityBoundaryTest {

    private static final String PASSWORD = "Str0ng!Pass";
    private static final String SECRET = "JBSWY3DPEHPK3PXP";

    @Autowired private RadiusServer radiusServer;
    @Autowired private UserRepository userRepository;
    @Autowired private UserService userService;
    @Autowired private TotpService totpService;
    @Autowired private OcraService ocraService;
    @Autowired private LoginService loginService;
    @Autowired private MfaPreAuthService mfaPreAuthService;
    @Autowired private UserOtpService userOtpService;
    @Autowired private AccountLockoutService lockoutService;
    @Autowired private RadiusChallengeSessionRepository challengeRepository;
    @Autowired private MfaApprovalRepository approvalRepository;
    @Autowired private AuthFailureRecordRepository failureRepository;
    @Autowired private SecurityPolicyRepository policyRepository;
    @Autowired private SecurityPolicyService policyService;
    @Autowired private AuthFailureStore failureStore;
    @Autowired private AuthAuditService auditService;
    @Autowired private OtpVerificationService otpVerificationService;
    @Autowired private PlatformTransactionManager transactionManager;
    @Autowired private Clock clock;

    private User user;

    @BeforeEach
    void setUp() {
        challengeRepository.deleteAll();
        failureRepository.deleteAll();
        approvalRepository.deleteAll();
        userRepository.deleteAll();
        SecurityPolicy policy = policyRepository.findByName(SecurityPolicy.DEFAULT_NAME).orElseThrow();
        policy.setMaxFailures(3);
        policy.setMfaMaxFailedAttempts(5);
        policyRepository.save(policy);
        user = userRepository.save(User.builder().username("unified").password(PASSWORD).secret(SECRET).build());
    }

    @AfterEach
    void tearDown() {
        failureRepository.deleteAll();
    }

    private String otp() {
        return String.format("%06d", totpService.generateOtp(SECRET));
    }

    private LoginResponse webLogin(String password, String otp) {
        return loginService.login(LoginRequest.builder().username("unified").password(password).otp(otp).build());
    }

    @Test
    void webFailuresLockRadiusAndOtpChannels() throws Exception {
        for (int i = 0; i < 3; i++) {
            assertEquals(LoginResponse.Status.INVALID_CREDENTIALS, webLogin("wrong", null).getStatus());
        }
        assertTrue(lockoutService.isLocked(user.getId()));
        assertFalse(mfaPreAuthService.preAuthenticate("unified", Integer.parseInt(otp())));
        assertEquals(false, userOtpService.validateUserOtp(user.getId(), Integer.parseInt(otp())).orElse(true));
        try (RadiusTestClient client = new RadiusTestClient(radiusServer.getLocalPort(), "unified-secret")) {
            assertEquals(ACCESS_REJECT, client.sendExpectingResponse(client.accessRequest("unified", PASSWORD, null)).getCode());
        }
        assertFalse(webLogin(PASSWORD, otp()).isAuthenticated());
    }

    @Test
    void unapprovedOutOfBandRequestsLockTheAccount() throws Exception {
        try (RadiusTestClient client = new RadiusTestClient(radiusServer.getLocalPort(), "unified-secret")) {
            for (int i = 0; i < 3; i++) {
                assertEquals(ACCESS_REJECT, client.sendExpectingResponse(client.accessRequest("unified", null, null)).getCode());
            }
        }
        assertTrue(lockoutService.isLocked(user.getId()));
        assertFalse(webLogin(PASSWORD, otp()).isAuthenticated());
    }

    @Test
    void successClearsFailures() {
        webLogin("wrong", null);
        webLogin("wrong", null);
        assertTrue(webLogin(PASSWORD, otp()).isAuthenticated());
        webLogin("wrong", null);
        webLogin("wrong", null);
        assertFalse(lockoutService.isLocked(user.getId()));
    }

    @Test
    void otpIsSingleUseAcrossChannels() throws Exception {
        String code = otp();
        assertTrue(webLogin(PASSWORD, code).isAuthenticated());
        assertFalse(mfaPreAuthService.preAuthenticate("unified", Integer.parseInt(code)));
        assertEquals(false, userOtpService.validateUserOtp(user.getId(), Integer.parseInt(code)).orElse(true));
        try (RadiusTestClient client = new RadiusTestClient(radiusServer.getLocalPort(), "unified-secret")) {
            RadiusPacket challenge = client.sendExpectingResponse(client.accessRequest("unified", PASSWORD, null));
            assertEquals(ACCESS_CHALLENGE, challenge.getCode());
            byte[] state = challenge.getAttribute(ATTR_STATE).orElseThrow().getValue();
            assertEquals(ACCESS_REJECT, client.sendExpectingResponse(client.accessRequest("unified", code, state)).getCode());
        }
    }

    @Test
    void concurrentOtpUseAcrossNodesAcceptsExactlyOne() throws Exception {
        int code = Integer.parseInt(otp());
        MfaPreAuthServiceImpl nodeA = new MfaPreAuthServiceImpl(userService, clock, policyService,
                failureStore, approvalRepository, transactionManager, auditService, otpVerificationService);
        MfaPreAuthServiceImpl nodeB = new MfaPreAuthServiceImpl(userService, clock, policyService,
                failureStore, approvalRepository, transactionManager, auditService, otpVerificationService);
        ExecutorService pool = Executors.newFixedThreadPool(8);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Boolean>> results = new ArrayList<>();
        for (int i = 0; i < 8; i++) {
            final int n = i;
            Callable<Boolean> task = () -> {
                start.await();
                return switch (n % 4) {
                    case 0 -> nodeA.preAuthenticate("unified", code);
                    case 1 -> nodeB.preAuthenticate("unified", code);
                    case 2 -> userOtpService.validateUserOtp(user.getId(), code).orElse(false);
                    default -> webLogin(PASSWORD, String.format("%06d", code)).isAuthenticated();
                };
            };
            results.add(pool.submit(task));
        }
        start.countDown();
        int accepted = 0;
        for (Future<Boolean> f : results) {
            if (f.get()) {
                accepted++;
            }
        }
        pool.shutdown();
        assertEquals(1, accepted);
    }

    @Test
    void ocraIsSingleUse() {
        String response = ocraService.generateOcra(SECRET, "challenge-1");
        assertTrue(userOtpService.validateUserOcra(user.getId(), "challenge-1", response).orElse(false));
        assertFalse(userOtpService.validateUserOcra(user.getId(), "challenge-1", response).orElse(true));
    }

    @Test
    void mismatchedChallengeResponseDoesNotDestroyChallenge() throws Exception {
        userRepository.save(User.builder().username("other").password(PASSWORD).secret(SECRET).build());
        try (RadiusTestClient client = new RadiusTestClient(radiusServer.getLocalPort(), "unified-secret")) {
            RadiusPacket challenge = client.sendExpectingResponse(client.accessRequest("unified", PASSWORD, null));
            byte[] state = challenge.getAttribute(ATTR_STATE).orElseThrow().getValue();
            assertEquals(ACCESS_REJECT, client.sendExpectingResponse(client.accessRequest("other", otp(), state)).getCode());
            assertEquals(ACCESS_ACCEPT, client.sendExpectingResponse(client.accessRequest("unified", otp(), state)).getCode());
        }
    }

    @Test
    void pendingSessionsInvalidatedOnCredentialChangeDeletionAndLockout() throws Exception {
        assertTrue(mfaPreAuthService.preAuthenticate("unified", Integer.parseInt(otp())));
        try (RadiusTestClient client = new RadiusTestClient(radiusServer.getLocalPort(), "unified-secret")) {
            assertEquals(ACCESS_CHALLENGE, client.sendExpectingResponse(client.accessRequest("unified", PASSWORD, null)).getCode());
        }
        assertEquals(1, approvalRepository.count());
        assertEquals(1, challengeRepository.count());
        User loaded = userService.getUserById(user.getId());
        loaded.setPassword("N3w!Password");
        userService.saveUser(loaded);
        assertEquals(0, approvalRepository.count());
        assertEquals(0, challengeRepository.count());

        try (RadiusTestClient client = new RadiusTestClient(radiusServer.getLocalPort(), "unified-secret")) {
            assertEquals(ACCESS_CHALLENGE, client.sendExpectingResponse(client.accessRequest("unified", "N3w!Password", null)).getCode());
        }
        assertEquals(1, challengeRepository.count());
        userOtpService.generateSecretForUser(user.getId());
        assertEquals(0, challengeRepository.count());

        try (RadiusTestClient client = new RadiusTestClient(radiusServer.getLocalPort(), "unified-secret")) {
            assertEquals(ACCESS_CHALLENGE, client.sendExpectingResponse(client.accessRequest("unified", "N3w!Password", null)).getCode());
        }
        for (int i = 0; i < 3; i++) {
            webLogin("wrong", null);
        }
        assertEquals(0, challengeRepository.count());

        lockoutService.recordSuccess(user.getId());
        try (RadiusTestClient client = new RadiusTestClient(radiusServer.getLocalPort(), "unified-secret")) {
            assertEquals(ACCESS_CHALLENGE, client.sendExpectingResponse(client.accessRequest("unified", "N3w!Password", null)).getCode());
        }
        userService.deleteUser(user.getId());
        assertEquals(0, challengeRepository.count());
    }

    @Test
    void approvalsOfRealmSimilarAccountsAreIsolated() throws Exception {
        User partner = userRepository.save(User.builder().username("unified@partner.example").password(PASSWORD)
                .secret("KRSXG5CTMVRXEZLU").build());
        assertTrue(mfaPreAuthService.preAuthenticate("unified", Integer.parseInt(otp())));
        try (RadiusTestClient client = new RadiusTestClient(radiusServer.getLocalPort(), "unified-secret")) {
            // Resolves to the partner account, which has no approval: rejected, unified's approval untouched.
            assertEquals(ACCESS_REJECT, client.sendExpectingResponse(
                    client.accessRequest("unified@partner.example", null, null)).getCode());
            assertTrue(mfaPreAuthService.hasActiveApproval("unified"));
            assertEquals(ACCESS_ACCEPT, client.sendExpectingResponse(client.accessRequest("CORP\\unified", null, null)).getCode());
        }
        // The unapproved request was charged to the partner account only.
        assertEquals(1, failureRepository.findByScopeAndSubject("RADIUS", String.valueOf(partner.getId()))
                .orElseThrow().getFailureCount());
        assertTrue(failureRepository.findByScopeAndSubject("RADIUS", String.valueOf(user.getId())).isEmpty());
    }

    @Test
    void concurrentGuessesAreBoundedByThreshold() throws Exception {
        int valid = Integer.parseInt(otp());
        ExecutorService pool = Executors.newFixedThreadPool(16);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Boolean>> results = new ArrayList<>();
        for (int i = 0; i < 32; i++) {
            final int guess = (valid + 1 + i) % 1_000_000;
            results.add(pool.submit(() -> {
                start.await();
                return userOtpService.validateUserOtp(user.getId(), guess).orElse(false);
            }));
        }
        start.countDown();
        for (Future<Boolean> f : results) {
            assertFalse(f.get());
        }
        pool.shutdown();
        assertTrue(lockoutService.isLocked(user.getId()));
        // Only as many attempts as the policy allows were evaluated.
        assertEquals(3, failureRepository.findByScopeAndSubject("RADIUS", String.valueOf(user.getId()))
                .orElseThrow().getFailureCount());
        // Locked everywhere, also on a freshly created node.
        assertTrue(new RadiusAuthGuard(policyService, failureStore, clock).isLocked(user.getId()));
        assertFalse(userOtpService.validateUserOtp(user.getId(), valid).orElse(true));
    }

    private long stableStep() throws InterruptedException {
        while (clock.millis() % 30_000L > 26_000L) {
            Thread.sleep(200);
        }
        return clock.millis() / 30_000L;
    }

    private static int wrongOtp(TotpServiceImpl totpImpl, String secret, long step) {
        int prev = totpImpl.generateOtp(secret, step - 1);
        int curr = totpImpl.generateOtp(secret, step);
        int next = totpImpl.generateOtp(secret, step + 1);
        int candidate = 100_001;
        while (candidate == prev || candidate == curr || candidate == next) {
            candidate++;
        }
        return candidate;
    }

    @Test
    void mfaPreAuthThresholdLocksAllChannelsAndCrossChannelSuccessClearsMfaFailures() throws Exception {
        TotpServiceImpl totpImpl = new TotpServiceImpl(new HmacOtpProcessor(), clock);
        long step = stableStep();
        int codeTMinus1 = totpImpl.generateOtp(SECRET, step - 1);
        int codeT = totpImpl.generateOtp(SECRET, step);
        int codeTPlus1 = totpImpl.generateOtp(SECRET, step + 1);
        int wrong = wrongOtp(totpImpl, SECRET, step);

        // Part A: MFA threshold < maxFailures must immediately lock every channel.
        SecurityPolicy policy = policyRepository.findByName(SecurityPolicy.DEFAULT_NAME).orElseThrow();
        policy.setMaxFailures(5);
        policy.setMfaMaxFailedAttempts(2);
        policyRepository.save(policy);

        assertFalse(mfaPreAuthService.preAuthenticate("unified", wrong));
        assertFalse(mfaPreAuthService.preAuthenticate("unified", wrong));

        assertTrue(lockoutService.isLocked(user.getId()));
        assertFalse(webLogin(PASSWORD, String.format("%06d", codeT)).isAuthenticated());
        assertEquals(false, userOtpService.validateUserOtp(user.getId(), codeT).orElse(true));
        String challenge = "12345678";
        assertEquals(false, userOtpService.validateUserOcra(
                user.getId(), challenge, ocraService.generateOcra(SECRET, challenge)).orElse(true));
        try (RadiusTestClient client = new RadiusTestClient(radiusServer.getLocalPort(), "unified-secret")) {
            assertEquals(ACCESS_REJECT, client.sendExpectingResponse(
                    client.accessRequest("unified", PASSWORD, null)).getCode());
        }
        assertFalse(mfaPreAuthService.hasActiveApproval("unified"));

        // Part B: Valid Web Login clears accumulated MFA pre-auth failures across channels.
        policy.setMaxFailures(5);
        policy.setMfaMaxFailedAttempts(5);
        policyRepository.save(policy);
        lockoutService.recordSuccess(user.getId());
        assertTrue(webLogin(PASSWORD, String.format("%06d", codeTMinus1)).isAuthenticated());

        for (int i = 0; i < 4; i++) {
            assertFalse(mfaPreAuthService.preAuthenticate("unified", wrong));
        }
        assertFalse(lockoutService.isLocked(user.getId()));
        assertTrue(webLogin(PASSWORD, String.format("%06d", codeT)).isAuthenticated());
        assertTrue(failureRepository.findByScopeAndSubject(AuthFailureRecord.SCOPE_MFA_PREAUTH, "unified").isEmpty());

        assertFalse(mfaPreAuthService.preAuthenticate("unified", wrong));
        assertFalse(mfaPreAuthService.preAuthenticate("unified", wrong));
        assertFalse(lockoutService.isLocked(user.getId()));
        assertTrue(mfaPreAuthService.preAuthenticate("unified", codeTPlus1));
    }

    @Test
    void mfaPreAuthLockoutIsIsolatedFromRealmDistinctAndUnknownAccounts() throws Exception {
        User partner = userRepository.save(User.builder()
                .username("unified@partner.example")
                .password(PASSWORD)
                .secret("KRSXG5CTMVRXEZLU")
                .build());
        TotpServiceImpl totpImpl = new TotpServiceImpl(new HmacOtpProcessor(), clock);
        long step = stableStep();
        int threshold = policyService.current().getMfaMaxFailedAttempts();
        int valid = totpImpl.generateOtp(SECRET, step);
        int wrongPartner = wrongOtp(totpImpl, "KRSXG5CTMVRXEZLU", step);

        for (int i = 0; i < threshold; i++) {
            assertFalse(mfaPreAuthService.preAuthenticate("unified@partner.example", wrongPartner));
            assertFalse(mfaPreAuthService.preAuthenticate("future@partner.example", wrongPartner));
        }

        assertTrue(lockoutService.isLocked(partner.getId()));
        assertFalse(lockoutService.isLocked(user.getId()));
        assertTrue(mfaPreAuthService.preAuthenticate("unified", valid));

        User future = userService.saveUser(User.builder()
                .username("future")
                .password(PASSWORD)
                .secret(SECRET)
                .build());
        assertFalse(lockoutService.isLocked(future.getId()));
        assertTrue(mfaPreAuthService.preAuthenticate("future", valid));
    }
}
