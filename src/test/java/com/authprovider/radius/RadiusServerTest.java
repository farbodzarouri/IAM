package com.authprovider.radius;

import com.authprovider.MutableClock;
import com.authprovider.config.RadiusProperties;
import com.authprovider.entity.SecurityPolicy;
import com.authprovider.entity.User;
import com.authprovider.repository.UserRepository;
import com.authprovider.service.SecurityPolicyService;
import com.authprovider.service.UserOtpService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static com.authprovider.radius.RadiusConstants.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class RadiusServerTest {

    private static final String SECRET = "testing123";
    private static final String PASSWORD = "P@ssw0rd";
    private static final int VALID_OTP = 123456;

    private RadiusProperties properties;
    private SecurityPolicy policy;
    private MutableClock clock;
    private UserRepository userRepository;
    private UserOtpService userOtpService;
    private RadiusChallengeStore challengeStore;
    private RadiusAuthenticationHandler handler;
    private RadiusServer server;
    private RadiusTestClient client;

    @BeforeEach
    void setUp() throws Exception {
        properties = new RadiusProperties();
        properties.setPort(0);
        properties.setBindAddress("127.0.0.1");

        policy = SecurityPolicy.builder()
                .name(SecurityPolicy.DEFAULT_NAME)
                .challengeTtlSeconds(60)
                .maxFailures(3)
                .build();
        SecurityPolicyService policyService = SecurityPolicyService.inMemory(policy);
        RadiusClientRegistry clientRegistry = RadiusClientRegistry.inMemory(SECRET);

        clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
        userRepository = mock(UserRepository.class);
        userOtpService = mock(UserOtpService.class);

        User alice = User.builder().id(1L).username("alice").password(PASSWORD).secret("JBSWY3DPEHPK3PXP").build();
        User bob = User.builder().id(2L).username("bob").password(PASSWORD).build();
        when(userRepository.findByUsername(anyString())).thenReturn(Optional.empty());
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(alice));
        when(userRepository.findByUsername("bob")).thenReturn(Optional.of(bob));
        when(userOtpService.validatePrimaryVerifiedOtp(anyLong(), any())).thenReturn(Optional.of(false));
        when(userOtpService.validatePrimaryVerifiedOtp(1L, VALID_OTP)).thenReturn(Optional.of(true));

        challengeStore = new RadiusChallengeStore(policyService, clock, new SecureRandom());
        RadiusAuthGuard guard = new RadiusAuthGuard(policyService, clock);
        handler = new RadiusAuthenticationHandler(
                new PrimaryCredentialVerifier(userRepository), userOtpService, challengeStore, guard,
                clientRegistry, policyService);
        server = new RadiusServer(properties, handler, challengeStore, guard, clock, clientRegistry);
        server.start();
        assertTrue(server.isRunning());
        client = new RadiusTestClient(server.getLocalPort(), SECRET);
    }

    @AfterEach
    void tearDown() {
        client.close();
        server.stop();
    }

    private byte[] obtainChallenge(String userName) throws Exception {
        RadiusPacket challenge = client.sendExpectingResponse(client.accessRequest(userName, PASSWORD, null));
        assertEquals(ACCESS_CHALLENGE, challenge.getCode());
        return challenge.getAttribute(ATTR_STATE).orElseThrow().getValue();
    }

    @Test
    void fullTwoStepAuthenticationSucceeds() throws Exception {
        RadiusPacket challenge = client.sendExpectingResponse(client.accessRequest("alice", PASSWORD, null));

        assertEquals(ACCESS_CHALLENGE, challenge.getCode());
        assertEquals("Enter your one-time passcode",
                challenge.getAttribute(ATTR_REPLY_MESSAGE).orElseThrow().getValueAsString());
        assertEquals(60, challenge.getAttribute(ATTR_SESSION_TIMEOUT).orElseThrow().getValueAsInteger());
        byte[] state = challenge.getAttribute(ATTR_STATE).orElseThrow().getValue();
        assertEquals(32, state.length);

        RadiusPacket accept = client.sendExpectingResponse(client.accessRequest("alice", "123456", state));
        assertEquals(ACCESS_ACCEPT, accept.getCode());
    }

    @Test
    void proxyStateIsEchoedInOrder() throws Exception {
        List<RadiusAttribute> proxyStates = List.of(
                RadiusAttribute.ofString(ATTR_PROXY_STATE, "first"),
                RadiusAttribute.ofString(ATTR_PROXY_STATE, "second"));
        RadiusPacket challenge = client.sendExpectingResponse(
                client.accessRequest("alice", PASSWORD, null, proxyStates, true));
        assertEquals(proxyStates, challenge.getAttributes(ATTR_PROXY_STATE));
    }

    @Test
    void wrongPasswordAndUnknownUserAreRejected() throws Exception {
        assertEquals(ACCESS_REJECT, client.sendExpectingResponse(client.accessRequest("alice", "wrong", null)).getCode());
        assertEquals(ACCESS_REJECT, client.sendExpectingResponse(client.accessRequest("mallory", PASSWORD, null)).getCode());
        assertEquals(0, challengeStore.size());
    }

    @Test
    void userWithoutEnrolledOtpIsRejected() throws Exception {
        assertEquals(ACCESS_REJECT, client.sendExpectingResponse(client.accessRequest("bob", PASSWORD, null)).getCode());
    }

    @Test
    void domainQualifiedUserNameIsResolved() throws Exception {
        RadiusPacket challenge = client.sendExpectingResponse(client.accessRequest("CORP\\alice", PASSWORD, null));
        assertEquals(ACCESS_CHALLENGE, challenge.getCode());
        byte[] state = challenge.getAttribute(ATTR_STATE).orElseThrow().getValue();
        assertEquals(ACCESS_ACCEPT, client.sendExpectingResponse(client.accessRequest("CORP\\alice", "123456", state)).getCode());
    }

    @Test
    void wrongOtpRejectsAndConsumesState() throws Exception {
        byte[] state = obtainChallenge("alice");
        assertEquals(ACCESS_REJECT, client.sendExpectingResponse(client.accessRequest("alice", "000000", state)).getCode());
        assertEquals(ACCESS_REJECT, client.sendExpectingResponse(client.accessRequest("alice", "123456", state)).getCode());
    }

    @Test
    void stateCannotBeReusedAfterSuccess() throws Exception {
        byte[] state = obtainChallenge("alice");
        assertEquals(ACCESS_ACCEPT, client.sendExpectingResponse(client.accessRequest("alice", "123456", state)).getCode());
        assertEquals(ACCESS_REJECT, client.sendExpectingResponse(client.accessRequest("alice", "123456", state)).getCode());
    }

    @Test
    void tamperedStateIsRejected() throws Exception {
        byte[] state = obtainChallenge("alice");
        byte[] tampered = state.clone();
        tampered[0] ^= 0x01;
        assertEquals(ACCESS_REJECT, client.sendExpectingResponse(client.accessRequest("alice", "123456", tampered)).getCode());
        assertEquals(ACCESS_REJECT, client.sendExpectingResponse(
                client.accessRequest("alice", "123456", Arrays.copyOf(state, 16))).getCode());
    }

    @Test
    void stateIsBoundToUserName() throws Exception {
        byte[] state = obtainChallenge("alice");
        assertEquals(ACCESS_REJECT, client.sendExpectingResponse(client.accessRequest("bob", "123456", state)).getCode());
        // The mismatched request must not destroy alice's pending challenge.
        assertEquals(ACCESS_ACCEPT, client.sendExpectingResponse(client.accessRequest("alice", "123456", state)).getCode());
        assertEquals(ACCESS_REJECT, client.sendExpectingResponse(client.accessRequest("alice", "123456", state)).getCode());
    }

    @Test
    void stateIsBoundToClientAddress() throws Exception {
        byte[] state = obtainChallenge("alice");
        RadiusTestClient.Request request = client.accessRequest("alice", "123456", state);
        RadiusPacket packet = RadiusPacket.decode(request.bytes(), request.bytes().length);
        byte[] response = handler.handle(packet, InetAddress.getByName("10.9.8.7")).orElseThrow();
        assertEquals(ACCESS_REJECT, response[0]);
        // The request from the wrong client leaves the challenge usable by the legitimate client.
        assertEquals(ACCESS_ACCEPT, client.sendExpectingResponse(client.accessRequest("alice", "123456", state)).getCode());
    }

    @Test
    void expiredChallengeIsRejected() throws Exception {
        byte[] state = obtainChallenge("alice");
        clock.advance(Duration.ofSeconds(61));
        assertEquals(ACCESS_REJECT, client.sendExpectingResponse(client.accessRequest("alice", "123456", state)).getCode());
    }

    @Test
    void challengeTtlIsConfigurable() throws Exception {
        policy.setChallengeTtlSeconds(5);
        RadiusPacket challenge = client.sendExpectingResponse(client.accessRequest("alice", PASSWORD, null));
        assertEquals(5, challenge.getAttribute(ATTR_SESSION_TIMEOUT).orElseThrow().getValueAsInteger());
        clock.advance(Duration.ofSeconds(5));
        byte[] state = challenge.getAttribute(ATTR_STATE).orElseThrow().getValue();
        assertEquals(ACCESS_REJECT, client.sendExpectingResponse(client.accessRequest("alice", "123456", state)).getCode());
    }

    @Test
    void otpCannotBeReusedForAnotherChallenge() throws Exception {
        when(userOtpService.validatePrimaryVerifiedOtp(1L, VALID_OTP))
                .thenReturn(Optional.of(true), Optional.of(false));
        byte[] first = obtainChallenge("alice");
        assertEquals(ACCESS_ACCEPT, client.sendExpectingResponse(client.accessRequest("alice", "123456", first)).getCode());
        byte[] second = obtainChallenge("alice");
        assertEquals(ACCESS_REJECT, client.sendExpectingResponse(client.accessRequest("alice", "123456", second)).getCode());
    }

    @Test
    void retransmittedRequestsReceiveIdenticalResponses() throws Exception {
        RadiusTestClient.Request first = client.accessRequest("alice", PASSWORD, null);
        RadiusPacket challenge = client.sendExpectingResponse(first);
        RadiusPacket retransmitted = client.sendExpectingResponse(first);
        assertArrayEquals(challenge.getRawBytes(), retransmitted.getRawBytes());
        assertEquals(1, challengeStore.size());

        byte[] state = challenge.getAttribute(ATTR_STATE).orElseThrow().getValue();
        RadiusTestClient.Request second = client.accessRequest("alice", "123456", state);
        RadiusPacket accept = client.sendExpectingResponse(second);
        assertEquals(ACCESS_ACCEPT, accept.getCode());
        RadiusPacket acceptAgain = client.sendExpectingResponse(second);
        assertArrayEquals(accept.getRawBytes(), acceptAgain.getRawBytes());
        verify(userOtpService, times(1)).validatePrimaryVerifiedOtp(eq(1L), any());
    }

    @Test
    void retransmissionCacheExpires() throws Exception {
        RadiusTestClient.Request request = client.accessRequest("alice", PASSWORD, null);
        RadiusPacket first = client.sendExpectingResponse(request);
        clock.advance(Duration.ofSeconds(properties.getDuplicateCacheSeconds() + 1));
        RadiusPacket second = client.sendExpectingResponse(request);
        assertFalse(Arrays.equals(first.getAttribute(ATTR_STATE).orElseThrow().getValue(),
                second.getAttribute(ATTR_STATE).orElseThrow().getValue()));
    }

    @Test
    void invalidMessageAuthenticatorIsSilentlyDiscarded() throws Exception {
        RadiusTestClient.Request request = client.accessRequest("alice", PASSWORD, null);
        byte[] bytes = request.bytes();
        bytes[HEADER_LENGTH + 2] ^= 0x01;
        assertTrue(client.send(request).isEmpty());
    }

    @Test
    void wrongSharedSecretIsSilentlyDiscarded() throws Exception {
        try (RadiusTestClient other = new RadiusTestClient(server.getLocalPort(), "not-the-secret")) {
            assertTrue(other.send(other.accessRequest("alice", PASSWORD, null)).isEmpty());
        }
    }

    @Test
    void requestsWithoutMessageAuthenticatorAreAcceptedByDefault() throws Exception {
        RadiusPacket challenge = client.sendExpectingResponse(
                client.accessRequest("alice", PASSWORD, null, List.of(), false));
        assertEquals(ACCESS_CHALLENGE, challenge.getCode());
    }

    @Test
    void messageAuthenticatorCanBeRequired() throws Exception {
        policy.setRequireMessageAuthenticator(true);
        assertTrue(client.send(client.accessRequest("alice", PASSWORD, null, List.of(), false)).isEmpty());
        assertEquals(ACCESS_CHALLENGE, client.sendExpectingResponse(client.accessRequest("alice", PASSWORD, null)).getCode());
    }

    @Test
    void eapRequestsAreHandledPerRfc3579() throws Exception {
        RadiusAttribute eap = new RadiusAttribute(ATTR_EAP_MESSAGE, new byte[]{2, 0, 0, 5, 1});
        assertTrue(client.send(client.raw(ACCESS_REQUEST,
                List.of(RadiusAttribute.ofString(ATTR_USER_NAME, "alice"), eap), false)).isEmpty());
        assertEquals(ACCESS_REJECT, client.sendExpectingResponse(client.raw(ACCESS_REQUEST,
                List.of(RadiusAttribute.ofString(ATTR_USER_NAME, "alice"), eap), true)).getCode());
    }

    @Test
    void chapRequestsAreRejected() throws Exception {
        RadiusPacket response = client.sendExpectingResponse(client.raw(ACCESS_REQUEST, List.of(
                RadiusAttribute.ofString(ATTR_USER_NAME, "alice"),
                new RadiusAttribute(ATTR_CHAP_PASSWORD, new byte[17])), true));
        assertEquals(ACCESS_REJECT, response.getCode());
    }

    @Test
    void statusServerIsAnswered() throws Exception {
        assertEquals(ACCESS_ACCEPT, client.sendExpectingResponse(client.raw(STATUS_SERVER, List.of(), true)).getCode());
        assertTrue(client.send(client.raw(STATUS_SERVER, List.of(), false)).isEmpty());
    }

    @Test
    void unsupportedCodesAreIgnored() throws Exception {
        assertTrue(client.send(client.raw(ACCOUNTING_REQUEST, List.of(), true)).isEmpty());
    }

    @Test
    void repeatedFailuresLockTheAccount() throws Exception {
        for (int i = 0; i < 3; i++) {
            assertEquals(ACCESS_REJECT, client.sendExpectingResponse(client.accessRequest("alice", "wrong", null)).getCode());
        }
        assertEquals(ACCESS_REJECT, client.sendExpectingResponse(client.accessRequest("alice", PASSWORD, null)).getCode());
        clock.advance(Duration.ofSeconds(policy.getLockoutSeconds() + 1));
        assertEquals(ACCESS_CHALLENGE, client.sendExpectingResponse(client.accessRequest("alice", PASSWORD, null)).getCode());
    }

    @Test
    void malformedPacketsAreIgnoredAndServerKeepsWorking() throws Exception {
        RadiusTestClient.Request garbage = new RadiusTestClient.Request(0, new byte[16],
                "not a radius packet at all".getBytes(StandardCharsets.UTF_8));
        assertTrue(client.send(garbage).isEmpty());
        assertEquals(ACCESS_CHALLENGE, client.sendExpectingResponse(client.accessRequest("alice", PASSWORD, null)).getCode());
    }

    @Test
    void challengeCapacityIsBounded() throws Exception {
        policy.setChallengeMaxPending(1);
        obtainChallenge("alice");
        assertEquals(ACCESS_REJECT, client.sendExpectingResponse(client.accessRequest("alice", PASSWORD, null)).getCode());
    }
}
