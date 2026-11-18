package com.authprovider.radius;

import com.authprovider.config.RadiusProperties;
import com.authprovider.entity.SecurityPolicy;
import com.authprovider.entity.User;
import com.authprovider.repository.RadiusClientRepository;
import com.authprovider.repository.UserRepository;
import com.authprovider.service.SecurityPolicyService;
import com.authprovider.service.TotpService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static com.authprovider.radius.RadiusConstants.*;
import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(properties = {
        "radius.port=0",
        "radius.bind-address=127.0.0.1",
        "iam.bootstrap.radius.shared-secret=integration-secret",
        "iam.bootstrap.policy.challenge-ttl-seconds=45"
})
class RadiusIntegrationTest {

    @Autowired
    private RadiusServer radiusServer;

    @Autowired
    private RadiusProperties radiusProperties;

    @Autowired
    private SecurityPolicyService policyService;

    @Autowired
    private RadiusClientRepository clientRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TotpService totpService;

    @Test
    void propertiesAndSeededDatabaseConfigAreBoundCleanly() {
        assertEquals("127.0.0.1", radiusProperties.getBindAddress());
        assertTrue(radiusServer.isRunning());
        SecurityPolicy policy = policyService.current();
        assertEquals(45, policy.getChallengeTtlSeconds());
        assertTrue(clientRepository.findAll().stream()
                .anyMatch(c -> "integration-secret".equals(c.getSharedSecret()) && c.isActive()));
    }

    @Test
    void authenticatesAgainstDatabaseUserWithTotp() throws Exception {
        String secret = "JBSWY3DPEHPK3PXP";
        userRepository.save(User.builder().username("rdg-user").password("Str0ng!Pass").secret(secret).build());

        try (RadiusTestClient client = new RadiusTestClient(radiusServer.getLocalPort(), "integration-secret")) {
            RadiusPacket challenge = client.sendExpectingResponse(client.accessRequest("rdg-user", "Str0ng!Pass", null));
            assertEquals(ACCESS_CHALLENGE, challenge.getCode());
            assertEquals(45, challenge.getAttribute(ATTR_SESSION_TIMEOUT).orElseThrow().getValueAsInteger());
            byte[] state = challenge.getAttribute(ATTR_STATE).orElseThrow().getValue();

            String otp = String.format("%06d", totpService.generateOtp(secret));
            RadiusPacket accept = client.sendExpectingResponse(client.accessRequest("rdg-user", otp, state));
            assertEquals(ACCESS_ACCEPT, accept.getCode());
        }
    }
}
