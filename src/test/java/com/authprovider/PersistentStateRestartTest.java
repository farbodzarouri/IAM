package com.authprovider;

import com.authprovider.entity.SecurityPolicy;
import com.authprovider.entity.User;
import com.authprovider.radius.RadiusAuthGuard;
import com.authprovider.repository.RadiusClientRepository;
import com.authprovider.repository.SecurityPolicyRepository;
import com.authprovider.repository.UserRepository;
import com.authprovider.service.MfaPreAuthService;
import com.authprovider.service.TotpService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

/** Authentication state and runtime configuration survive an application restart. */
class PersistentStateRestartTest {

    @TempDir
    Path dir;

    private ConfigurableApplicationContext start(String sharedSecret) {
        return new SpringApplicationBuilder(IamApplication.class).run(
                "--server.port=0",
                "--radius.enabled=false",
                "--iam.bootstrap.radius.shared-secret=" + sharedSecret,
                "--iam.bootstrap.policy.max-failures=2",
                "--spring.datasource.url=jdbc:h2:file:" + dir.resolve("iam").toAbsolutePath() + ";DB_CLOSE_ON_EXIT=FALSE",
                "--spring.jpa.hibernate.ddl-auto=update");
    }

    @Test
    void lockoutsApprovalsAndConfigurationSurviveRestart() {
        String secret = "JBSWY3DPEHPK3PXP";
        Long userId;
        try (ConfigurableApplicationContext first = start("first-secret")) {
            userId = first.getBean(com.authprovider.service.UserService.class)
                    .saveUser(User.builder().username("restart-user").password("pw").otpToken(com.authprovider.TestUsers.token(secret)).build()).getId();
            first.getBean(com.authprovider.service.UserService.class)
                    .saveUser(User.builder().username("approved-user").password("pw").otpToken(com.authprovider.TestUsers.token(secret)).build());
            RadiusAuthGuard guard = first.getBean(RadiusAuthGuard.class);
            guard.recordFailure(userId);
            guard.recordFailure(userId);
            assertTrue(guard.isLocked(userId));
            int otp = first.getBean(TotpService.class).generateOtp(secret);
            // The lockout applies to every channel, including MFA pre-authentication.
            assertFalse(first.getBean(MfaPreAuthService.class).preAuthenticate("restart-user", otp));
            assertTrue(first.getBean(MfaPreAuthService.class).preAuthenticate("approved-user", otp));

            SecurityPolicy policy = first.getBean(SecurityPolicyRepository.class)
                    .findByName(SecurityPolicy.DEFAULT_NAME).orElseThrow();
            policy.setChallengeTtlSeconds(77);
            first.getBean(SecurityPolicyRepository.class).save(policy);
        }
        try (ConfigurableApplicationContext second = start("second-secret")) {
            assertTrue(second.getBean(RadiusAuthGuard.class).isLocked(userId));
            assertFalse(second.getBean(MfaPreAuthService.class).consumeApproval("restart-user"));
            assertTrue(second.getBean(MfaPreAuthService.class).consumeApproval("approved-user"));
            // An initialized database is not re-seeded: runtime changes are kept.
            assertEquals(77, second.getBean(SecurityPolicyRepository.class)
                    .findByName(SecurityPolicy.DEFAULT_NAME).orElseThrow().getChallengeTtlSeconds());
            assertTrue(second.getBean(RadiusClientRepository.class).findAll().stream()
                    .allMatch(c -> "first-secret".equals(c.getSharedSecret())));
        }
    }
}
