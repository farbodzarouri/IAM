package com.authprovider.radius;

import com.authprovider.entity.User;
import com.authprovider.repository.UserRepository;
import com.authprovider.service.TotpService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static com.authprovider.radius.RadiusConstants.*;
import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(properties = {
        "radius.port=0",
        "radius.bind-address=127.0.0.1",
        "radius.shared-secret=integration-secret",
        "radius.challenge.ttl-seconds=45"
})
class RadiusIntegrationTest {

    @Autowired
    private RadiusServer radiusServer;

    @Autowired
    private RadiusProperties radiusProperties;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TotpService totpService;

    @Test
    void propertiesAreBoundFromConfiguration() {
        assertEquals("integration-secret", radiusProperties.getSharedSecret());
        assertEquals(45, radiusProperties.getChallenge().getTtlSeconds());
        assertTrue(radiusServer.isRunning());
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
