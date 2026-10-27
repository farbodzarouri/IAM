package com.authprovider;

import com.authprovider.entity.User;
import com.authprovider.repository.UserRepository;
import com.authprovider.service.SecretGenerator;
import com.authprovider.service.TotpService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(properties = {
        "radius.port=18126",
        "radius.shared-secret=testing123",
        "radius.shared.secret=testing123",
        "radius.challenge.ttl-seconds=3"
})
@AutoConfigureMockMvc
public class RadiusInBandMfaGraderTest {

    private static final int RADIUS_PORT = 18126;
    private static final String SHARED_SECRET = "testing123";

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private SecretGenerator secretGenerator;

    @Autowired
    private TotpService totpService;

    private final SecureRandom secureRandom = new SecureRandom();

    private User alice;
    private User bob;

    @BeforeEach
    public void setUp() {
        userRepository.deleteAll();

        alice = User.builder()
                .username("alice")
                .password("AlicePass123!")
                .secret(secretGenerator.generateSecret())
                .build();

        bob = User.builder()
                .username("bob")
                .password("BobPass456!")
                .secret(secretGenerator.generateSecret())
                .build();

        userRepository.saveAll(List.of(alice, bob));
    }

    @Test
    public void testHappyPath_SuccessfulTwoStepChallengeResponse() throws Exception {
        byte[] reqAuth1 = randomAuthenticator();
        byte[] packet1 = buildAccessRequest(10, reqAuth1, "alice", "AlicePass123!", null, false, false);
        byte[] resp1 = sendRadiusPacket(packet1, 2000);

        assertNotNull(resp1, "Server must respond to initial Access-Request");
        assertEquals(11, resp1[0] & 0xFF, "Valid primary credentials must trigger Access-Challenge (Code 11)");
        assertValidResponseAuthenticator(resp1, reqAuth1);

        byte[] state = extractAttribute(resp1, 24);
        assertNotNull(state, "Access-Challenge must include State attribute (Type 24)");
        assertTrue(state.length > 0, "State attribute must not be empty");

        byte[] replyMsg = extractAttribute(resp1, 18);
        assertNotNull(replyMsg, "Access-Challenge must include Reply-Message attribute (Type 18)");
        assertTrue(replyMsg.length > 0, "Reply-Message attribute must not be empty");

        String validOtp = String.format("%06d", totpService.generateOtp(alice.getSecret()));
        byte[] reqAuth2 = randomAuthenticator();
        byte[] packet2 = buildAccessRequest(11, reqAuth2, "alice", validOtp, state, false, false);
        byte[] resp2 = sendRadiusPacket(packet2, 2000);

        assertNotNull(resp2, "Server must respond to second-step Access-Request with OTP");
        assertEquals(2, resp2[0] & 0xFF, "Valid OTP and State must return Access-Accept (Code 2)");
        assertValidResponseAuthenticator(resp2, reqAuth2);
    }

    @Test
    public void testTurn1_WrongPassword_ReturnsAccessReject() throws Exception {
        byte[] reqAuth = randomAuthenticator();
        byte[] packet = buildAccessRequest(20, reqAuth, "alice", "WrongPassword999!", null, false, false);
        byte[] resp = sendRadiusPacket(packet, 2000);

        assertNotNull(resp, "Server must respond to invalid primary credentials");
        assertEquals(3, resp[0] & 0xFF, "Invalid primary password must immediately return Access-Reject (Code 3)");
        assertValidResponseAuthenticator(resp, reqAuth);
    }

    @Test
    public void testTurn1_UnknownUser_ReturnsAccessReject() throws Exception {
        byte[] reqAuth = randomAuthenticator();
        byte[] packet = buildAccessRequest(25, reqAuth, "ghostuser", "SomePassword123!", null, false, false);
        byte[] resp = sendRadiusPacket(packet, 2000);

        assertNotNull(resp, "Server must respond to nonexistent user");
        assertEquals(3, resp[0] & 0xFF, "Nonexistent user must return Access-Reject (Code 3)");
        assertValidResponseAuthenticator(resp, reqAuth);
    }

    @Test
    public void testTurn2_WrongOtp_ReturnsAccessReject() throws Exception {
        byte[] reqAuth1 = randomAuthenticator();
        byte[] packet1 = buildAccessRequest(30, reqAuth1, "alice", "AlicePass123!", null, false, false);
        byte[] resp1 = sendRadiusPacket(packet1, 2000);

        assertNotNull(resp1, "Initial request must succeed");
        assertEquals(11, resp1[0] & 0xFF, "Must return Access-Challenge (Code 11)");
        byte[] state = extractAttribute(resp1, 24);
        assertNotNull(state, "State attribute required");

        byte[] reqAuth2 = randomAuthenticator();
        byte[] packet2 = buildAccessRequest(31, reqAuth2, "alice", "000000", state, false, false);
        byte[] resp2 = sendRadiusPacket(packet2, 2000);

        assertNotNull(resp2, "Server must respond to invalid OTP");
        assertEquals(3, resp2[0] & 0xFF, "Invalid OTP must return Access-Reject (Code 3)");
        assertValidResponseAuthenticator(resp2, reqAuth2);
    }

    @Test
    public void testTurn2_StateReplayProtection_ReusedStateRejected() throws Exception {
        byte[] reqAuth1 = randomAuthenticator();
        byte[] packet1 = buildAccessRequest(40, reqAuth1, "alice", "AlicePass123!", null, false, false);
        byte[] resp1 = sendRadiusPacket(packet1, 2000);

        assertNotNull(resp1);
        assertEquals(11, resp1[0] & 0xFF);
        byte[] state = extractAttribute(resp1, 24);
        assertNotNull(state);

        String validOtp = String.format("%06d", totpService.generateOtp(alice.getSecret()));
        byte[] reqAuth2 = randomAuthenticator();
        byte[] packet2 = buildAccessRequest(41, reqAuth2, "alice", validOtp, state, false, false);
        byte[] resp2 = sendRadiusPacket(packet2, 2000);

        assertNotNull(resp2);
        assertEquals(2, resp2[0] & 0xFF, "First verification must accept");

        // Attempt replay attack with the same State token and valid OTP
        byte[] reqAuthReplay = randomAuthenticator();
        byte[] replayPacket = buildAccessRequest(42, reqAuthReplay, "alice", validOtp, state, false, false);
        byte[] respReplay = sendRadiusPacket(replayPacket, 2000);

        assertNotNull(respReplay, "Server must respond to replayed State attempt");
        assertEquals(3, respReplay[0] & 0xFF, "Reused State attribute must be rejected (single-use constraint)");
        assertValidResponseAuthenticator(respReplay, reqAuthReplay);
    }

    @Test
    public void testTurn2_StateTampering_ReturnsAccessReject() throws Exception {
        byte[] reqAuth1 = randomAuthenticator();
        byte[] packet1 = buildAccessRequest(50, reqAuth1, "alice", "AlicePass123!", null, false, false);
        byte[] resp1 = sendRadiusPacket(packet1, 2000);

        assertNotNull(resp1);
        assertEquals(11, resp1[0] & 0xFF);
        byte[] state = extractAttribute(resp1, 24);
        assertNotNull(state);

        // Tamper with State token
        byte[] tamperedState = Arrays.copyOf(state, state.length);
        tamperedState[0] ^= 0xA5;

        String validOtp = String.format("%06d", totpService.generateOtp(alice.getSecret()));
        byte[] reqAuth2 = randomAuthenticator();
        byte[] packet2 = buildAccessRequest(51, reqAuth2, "alice", validOtp, tamperedState, false, false);
        byte[] resp2 = sendRadiusPacket(packet2, 2000);

        assertNotNull(resp2, "Server must respond to tampered State");
        assertEquals(3, resp2[0] & 0xFF, "Tampered State token must return Access-Reject (Code 3)");
        assertValidResponseAuthenticator(resp2, reqAuth2);
    }

    @Test
    public void testTurn2_StateExpiration_TtlEnforced() throws Exception {
        byte[] reqAuth1 = randomAuthenticator();
        byte[] packet1 = buildAccessRequest(60, reqAuth1, "alice", "AlicePass123!", null, false, false);
        byte[] resp1 = sendRadiusPacket(packet1, 2000);

        assertNotNull(resp1);
        assertEquals(11, resp1[0] & 0xFF);
        byte[] state = extractAttribute(resp1, 24);
        assertNotNull(state);

        // Wait for TTL (3 seconds configured in properties) to expire
        Thread.sleep(3500);

        String validOtp = String.format("%06d", totpService.generateOtp(alice.getSecret()));
        byte[] reqAuth2 = randomAuthenticator();
        byte[] packet2 = buildAccessRequest(61, reqAuth2, "alice", validOtp, state, false, false);
        byte[] resp2 = sendRadiusPacket(packet2, 2000);

        assertNotNull(resp2, "Server must respond after TTL expiration");
        assertEquals(3, resp2[0] & 0xFF, "Expired challenge session must return Access-Reject (Code 3)");
        assertValidResponseAuthenticator(resp2, reqAuth2);
    }

    @Test
    public void testRetransmission_Packet1_ReturnsCachedChallengeWithSameState() throws Exception {
        byte[] reqAuth1 = randomAuthenticator();
        byte[] packet1 = buildAccessRequest(70, reqAuth1, "alice", "AlicePass123!", null, false, false);

        byte[] resp1a = sendRadiusPacket(packet1, 2000);
        assertNotNull(resp1a);
        assertEquals(11, resp1a[0] & 0xFF);
        byte[] state1 = extractAttribute(resp1a, 24);
        assertNotNull(state1);

        // Retransmit identical packet from another socket instance (simulating network retransmission)
        byte[] resp1b = sendRadiusPacket(packet1, 2000);
        assertNotNull(resp1b, "Server must retransmit cached Access-Challenge");
        assertEquals(11, resp1b[0] & 0xFF);
        byte[] state2 = extractAttribute(resp1b, 24);
        assertNotNull(state2);

        assertArrayEquals(state1, state2, "Retransmitted packet must return identical State token without generating new session");

        // The original State must still be valid for completing MFA
        String validOtp = String.format("%06d", totpService.generateOtp(alice.getSecret()));
        byte[] reqAuth2 = randomAuthenticator();
        byte[] packet2 = buildAccessRequest(71, reqAuth2, "alice", validOtp, state1, false, false);
        byte[] resp2 = sendRadiusPacket(packet2, 2000);

        assertNotNull(resp2);
        assertEquals(2, resp2[0] & 0xFF, "Session must remain valid and accept OTP following retransmissions");
    }

    @Test
    public void testRetransmission_Packet2_ReturnsCachedAccept() throws Exception {
        byte[] reqAuth1 = randomAuthenticator();
        byte[] packet1 = buildAccessRequest(75, reqAuth1, "alice", "AlicePass123!", null, false, false);
        byte[] resp1 = sendRadiusPacket(packet1, 2000);
        assertNotNull(resp1);
        byte[] state = extractAttribute(resp1, 24);
        assertNotNull(state);

        String validOtp = String.format("%06d", totpService.generateOtp(alice.getSecret()));
        byte[] reqAuth2 = randomAuthenticator();
        byte[] packet2 = buildAccessRequest(76, reqAuth2, "alice", validOtp, state, false, false);

        byte[] resp2a = sendRadiusPacket(packet2, 2000);
        assertNotNull(resp2a);
        assertEquals(2, resp2a[0] & 0xFF);

        // Retransmit Packet 2
        byte[] resp2b = sendRadiusPacket(packet2, 2000);
        assertNotNull(resp2b, "Server must retransmit cached Access-Accept");
        assertEquals(2, resp2b[0] & 0xFF, "Retransmission must return Access-Accept from cache rather than failing as replay");
    }

    @Test
    public void testActiveDirectoryDomainPrefix_Normalized() throws Exception {
        byte[] reqAuth1 = randomAuthenticator();
        byte[] packet1 = buildAccessRequest(80, reqAuth1, "CONTOSO\\alice", "AlicePass123!", null, false, false);
        byte[] resp1 = sendRadiusPacket(packet1, 2000);

        assertNotNull(resp1, "Server must handle DOMAIN\\username prefix");
        assertEquals(11, resp1[0] & 0xFF, "DOMAIN\\alice must resolve to alice and issue Access-Challenge");
        byte[] state = extractAttribute(resp1, 24);
        assertNotNull(state);

        String validOtp = String.format("%06d", totpService.generateOtp(alice.getSecret()));
        byte[] reqAuth2 = randomAuthenticator();
        byte[] packet2 = buildAccessRequest(81, reqAuth2, "CONTOSO\\alice", validOtp, state, false, false);
        byte[] resp2 = sendRadiusPacket(packet2, 2000);

        assertNotNull(resp2);
        assertEquals(2, resp2[0] & 0xFF, "DOMAIN\\alice must complete authentication successfully");
    }

    @Test
    public void testMessageAuthenticator_ValidAndTampered() throws Exception {
        // Case A: Valid Message-Authenticator (RFC 3579)
        byte[] reqAuth1 = randomAuthenticator();
        byte[] packetValidMsgAuth = buildAccessRequest(90, reqAuth1, "alice", "AlicePass123!", null, true, false);
        byte[] resp1 = sendRadiusPacket(packetValidMsgAuth, 2000);

        assertNotNull(resp1, "Server must respond to packet with valid Message-Authenticator");
        assertEquals(11, resp1[0] & 0xFF);
        assertValidResponseMessageAuthenticatorIfPresent(resp1, reqAuth1);

        // Case B: Tampered Message-Authenticator must be dropped or rejected
        byte[] reqAuth2 = randomAuthenticator();
        byte[] packetTamperedMsgAuth = buildAccessRequest(91, reqAuth2, "alice", "AlicePass123!", null, true, true);
        byte[] resp2 = sendRadiusPacket(packetTamperedMsgAuth, 1500);

        if (resp2 != null) {
            assertEquals(3, resp2[0] & 0xFF, "Tampered Message-Authenticator must return Access-Reject if not silently dropped");
        }
    }

    @Test
    public void testConcurrentUsers_IndependentChallenges() throws Exception {
        byte[] reqAuthA1 = randomAuthenticator();
        byte[] packetA1 = buildAccessRequest(100, reqAuthA1, "alice", "AlicePass123!", null, false, false);
        byte[] respA1 = sendRadiusPacket(packetA1, 2000);
        assertNotNull(respA1);
        assertEquals(11, respA1[0] & 0xFF);
        byte[] stateA = extractAttribute(respA1, 24);
        assertNotNull(stateA);

        byte[] reqAuthB1 = randomAuthenticator();
        byte[] packetB1 = buildAccessRequest(101, reqAuthB1, "bob", "BobPass456!", null, false, false);
        byte[] respB1 = sendRadiusPacket(packetB1, 2000);
        assertNotNull(respB1);
        assertEquals(11, respB1[0] & 0xFF);
        byte[] stateB = extractAttribute(respB1, 24);
        assertNotNull(stateB);

        assertFalse(Arrays.equals(stateA, stateB), "Concurrent users must receive distinct State tokens");

        // Bob completes Turn 2 first
        String validBobOtp = String.format("%06d", totpService.generateOtp(bob.getSecret()));
        byte[] reqAuthB2 = randomAuthenticator();
        byte[] packetB2 = buildAccessRequest(102, reqAuthB2, "bob", validBobOtp, stateB, false, false);
        byte[] respB2 = sendRadiusPacket(packetB2, 2000);
        assertNotNull(respB2);
        assertEquals(2, respB2[0] & 0xFF, "Bob must succeed");

        // Alice completes Turn 2 second
        String validAliceOtp = String.format("%06d", totpService.generateOtp(alice.getSecret()));
        byte[] reqAuthA2 = randomAuthenticator();
        byte[] packetA2 = buildAccessRequest(103, reqAuthA2, "alice", validAliceOtp, stateA, false, false);
        byte[] respA2 = sendRadiusPacket(packetA2, 2000);
        assertNotNull(respA2);
        assertEquals(2, respA2[0] & 0xFF, "Alice must succeed without interference from Bob");
    }

    @Test
    public void testCaseInsensitiveUsername_Succeeds() throws Exception {
        byte[] reqAuth1 = randomAuthenticator();
        byte[] packet1 = buildAccessRequest(110, reqAuth1, "ALICE", "AlicePass123!", null, false, false);
        byte[] resp1 = sendRadiusPacket(packet1, 2000);

        assertNotNull(resp1, "Server must handle case-insensitive usernames");
        assertEquals(11, resp1[0] & 0xFF, "ALICE must match alice and return Access-Challenge");
        byte[] state = extractAttribute(resp1, 24);
        assertNotNull(state);

        String validOtp = String.format("%06d", totpService.generateOtp(alice.getSecret()));
        byte[] reqAuth2 = randomAuthenticator();
        byte[] packet2 = buildAccessRequest(111, reqAuth2, "ALICE", validOtp, state, false, false);
        byte[] resp2 = sendRadiusPacket(packet2, 2000);

        assertNotNull(resp2);
        assertEquals(2, resp2[0] & 0xFF, "ALICE must complete authentication successfully");
    }

    @Test
    public void testMalformedPacket_DoesNotCrashServer() throws Exception {
        // Send truncated garbage packet (5 bytes, less than RFC 2865 20-byte header)
        byte[] garbage = new byte[]{1, 2, 0, 5, 99};
        byte[] garbageResp = sendRadiusPacket(garbage, 500);
        // Garbage should either be silently dropped (null) or rejected
        if (garbageResp != null) {
            assertEquals(3, garbageResp[0] & 0xFF);
        }

        // Verify server is still completely operational
        byte[] reqAuth = randomAuthenticator();
        byte[] validPacket = buildAccessRequest(120, reqAuth, "alice", "AlicePass123!", null, false, false);
        byte[] validResp = sendRadiusPacket(validPacket, 2000);

        assertNotNull(validResp, "Server UDP listener must remain operational after receiving malformed packet");
        assertEquals(11, validResp[0] & 0xFF, "Server must continue serving valid requests normally");
    }

    private byte[] randomAuthenticator() {
        byte[] auth = new byte[16];
        secureRandom.nextBytes(auth);
        return auth;
    }

    private byte[] buildAccessRequest(int identifier, byte[] requestAuthenticator, String username,
                                      String passwordOrOtp, byte[] stateAttribute,
                                      boolean includeMessageAuthenticator, boolean tamperMessageAuthenticator) throws Exception {
        byte[] userBytes = username.getBytes(StandardCharsets.UTF_8);
        byte[] obfuscatedPassword = obfuscatePassword(passwordOrOtp, requestAuthenticator, SHARED_SECRET);

        ByteArrayOutputStream attrs = new ByteArrayOutputStream();

        // Attribute 1: User-Name
        attrs.write(1);
        attrs.write(2 + userBytes.length);
        attrs.write(userBytes);

        // Attribute 2: User-Password
        attrs.write(2);
        attrs.write(2 + obfuscatedPassword.length);
        attrs.write(obfuscatedPassword);

        // Attribute 24: State (if present)
        if (stateAttribute != null && stateAttribute.length > 0) {
            attrs.write(24);
            attrs.write(2 + stateAttribute.length);
            attrs.write(stateAttribute);
        }

        // Attribute 80: Message-Authenticator (if requested)
        int msgAuthOffset = -1;
        if (includeMessageAuthenticator) {
            msgAuthOffset = 20 + attrs.size() + 2;
            attrs.write(80);
            attrs.write(18);
            attrs.write(new byte[16]);
        }

        byte[] attrBytes = attrs.toByteArray();
        int totalLength = 20 + attrBytes.length;
        ByteBuffer buf = ByteBuffer.allocate(totalLength);
        buf.put((byte) 1); // Code 1 = Access-Request
        buf.put((byte) (identifier & 0xFF));
        buf.putShort((short) totalLength);
        buf.put(requestAuthenticator);
        buf.put(attrBytes);
        byte[] packet = buf.array();

        if (includeMessageAuthenticator) {
            Mac mac = Mac.getInstance("HmacMD5");
            mac.init(new SecretKeySpec(SHARED_SECRET.getBytes(StandardCharsets.UTF_8), "HmacMD5"));
            byte[] hmac = mac.doFinal(packet);
            if (tamperMessageAuthenticator) {
                hmac[0] ^= 0x5A;
            }
            System.arraycopy(hmac, 0, packet, msgAuthOffset, 16);
        }
        return packet;
    }

    private byte[] obfuscatePassword(String password, byte[] requestAuthenticator, String sharedSecret) throws Exception {
        byte[] pwBytes = password.getBytes(StandardCharsets.UTF_8);
        int len = ((pwBytes.length + 15) / 16) * 16;
        if (len == 0) len = 16;
        byte[] padded = new byte[len];
        System.arraycopy(pwBytes, 0, padded, 0, pwBytes.length);

        byte[] secretBytes = sharedSecret.getBytes(StandardCharsets.UTF_8);
        byte[] cipher = new byte[len];
        MessageDigest md5 = MessageDigest.getInstance("MD5");

        byte[] prev = requestAuthenticator;
        for (int i = 0; i < len; i += 16) {
            md5.reset();
            md5.update(secretBytes);
            md5.update(prev);
            byte[] digest = md5.digest();
            for (int j = 0; j < 16; j++) {
                cipher[i + j] = (byte) (padded[i + j] ^ digest[j]);
            }
            prev = Arrays.copyOfRange(cipher, i, i + 16);
        }
        return cipher;
    }

    private byte[] sendRadiusPacket(byte[] packetBytes, int timeoutMs) throws Exception {
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(timeoutMs);
            DatagramPacket req = new DatagramPacket(
                    packetBytes, packetBytes.length, InetAddress.getByName("127.0.0.1"), RADIUS_PORT);
            socket.send(req);

            byte[] buf = new byte[4096];
            DatagramPacket resp = new DatagramPacket(buf, buf.length);
            try {
                socket.receive(resp);
                return Arrays.copyOf(resp.getData(), resp.getLength());
            } catch (SocketTimeoutException e) {
                return null;
            }
        }
    }

    private byte[] extractAttribute(byte[] responsePacket, int targetType) {
        int pos = 20;
        while (pos + 2 <= responsePacket.length) {
            int type = responsePacket[pos] & 0xFF;
            int len = responsePacket[pos + 1] & 0xFF;
            if (len < 2 || pos + len > responsePacket.length) {
                break;
            }
            if (type == targetType) {
                return Arrays.copyOfRange(responsePacket, pos + 2, pos + len);
            }
            pos += len;
        }
        return null;
    }

    private void assertValidResponseAuthenticator(byte[] responsePacket, byte[] requestAuthenticator) throws Exception {
        assertTrue(responsePacket.length >= 20, "RADIUS response must be at least 20 bytes");
        int declaredLen = ((responsePacket[2] & 0xFF) << 8) | (responsePacket[3] & 0xFF);
        assertEquals(responsePacket.length, declaredLen, "RADIUS declared Length must match UDP payload length");

        byte[] actualRespAuth = Arrays.copyOfRange(responsePacket, 4, 20);
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        md5.update(responsePacket, 0, 4);
        md5.update(requestAuthenticator);
        if (responsePacket.length > 20) {
            md5.update(responsePacket, 20, responsePacket.length - 20);
        }
        md5.update(SHARED_SECRET.getBytes(StandardCharsets.UTF_8));
        byte[] expectedRespAuth = md5.digest();

        assertArrayEquals(expectedRespAuth, actualRespAuth,
                "Invalid RFC 2865 MD5 Response Authenticator in RADIUS reply");
    }

    private void assertValidResponseMessageAuthenticatorIfPresent(byte[] responsePacket, byte[] requestAuthenticator) throws Exception {
        int pos = 20;
        while (pos + 2 <= responsePacket.length) {
            int type = responsePacket[pos] & 0xFF;
            int len = responsePacket[pos + 1] & 0xFF;
            if (len < 2 || pos + len > responsePacket.length) {
                break;
            }
            if (type == 80 && len == 18) {
                byte[] actualHmac = Arrays.copyOfRange(responsePacket, pos + 2, pos + 18);
                byte[] copy = Arrays.copyOf(responsePacket, responsePacket.length);
                System.arraycopy(requestAuthenticator, 0, copy, 4, 16);
                Arrays.fill(copy, pos + 2, pos + 18, (byte) 0);

                Mac mac = Mac.getInstance("HmacMD5");
                mac.init(new SecretKeySpec(SHARED_SECRET.getBytes(StandardCharsets.UTF_8), "HmacMD5"));
                byte[] expectedHmac = mac.doFinal(copy);
                assertArrayEquals(expectedHmac, actualHmac,
                        "Invalid RFC 3579 HMAC-MD5 Message-Authenticator in RADIUS response");
                return;
            }
            pos += len;
        }
    }
}
