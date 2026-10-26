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
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {
        "radius.port=18125",
        "radius.shared-secret=testing123",
        "radius.mfa.ttl-seconds=3"
})
@AutoConfigureMockMvc
public class RadiusMfaAuthenticationTest {

    private static final int RADIUS_PORT = 18125;
    private static final String SHARED_SECRET = "testing123";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private SecretGenerator secretGenerator;

    @Autowired
    private TotpService totpService;

    private final SecureRandom secureRandom = new SecureRandom();

    @BeforeEach
    public void cleanUp() {
        userRepository.deleteAll();
    }

    @Test
    public void testNoExternalDependenciesAddedToPom() throws Exception {
        String pom = Files.readString(Path.of("pom.xml"), StandardCharsets.UTF_8);
        long dependencyCount = pom.split("<dependency>", -1).length - 1;
        assertEquals(11L, dependencyCount, "No external dependencies may be added to pom.xml");
    }

    private User createUserWithSecret(String username) {
        String secret = secretGenerator.generateSecret();
        User user = User.builder()
                .username(username)
                .password("password123")
                .secret(secret)
                .build();
        return userRepository.save(user);
    }

    @Test
    public void testRestPreAuthAndRadiusAcceptThenSingleUseRejectAndRetransmissionCache() throws Exception {
        User alice = createUserWithSecret("alice");
        int otp = totpService.generateOtp(alice.getSecret());

        mockMvc.perform(post("/v1/api/mfa/preauth")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice\",\"otp\":" + otp + "}"))
                .andExpect(status().isOk())
                .andExpect(content().string("true"));

        byte[] reqAuth1 = randomAuthenticator();
        byte[] packet1 = buildAccessRequest(10, reqAuth1, "alice", false, false);

        byte[] resp1 = sendRadiusPacket(packet1, 1500);
        assertNotNull(resp1, "Expected RADIUS response for pre-authenticated user");
        assertEquals(2, resp1[0] & 0xFF, "Expected Access-Accept (Code 2)");
        assertEquals(10, resp1[1] & 0xFF, "Expected matching Identifier 10");
        assertValidResponseAuthenticator(resp1, reqAuth1);

        // Retransmission of the exact same packet (same Identifier + same Request Authenticator)
        // must return the cached Access-Accept rather than failing
        byte[] respRetry = sendRadiusPacket(packet1, 1500);
        assertNotNull(respRetry, "Expected cached RADIUS response on UDP retransmission");
        assertEquals(2, respRetry[0] & 0xFF, "Retransmitted Access-Request must still receive Access-Accept (Code 2)");
        assertEquals(10, respRetry[1] & 0xFF);
        assertValidResponseAuthenticator(respRetry, reqAuth1);

        // A new Access-Request (different Identifier / Request Authenticator) after consumption must be rejected
        byte[] reqAuth2 = randomAuthenticator();
        byte[] packet2 = buildAccessRequest(11, reqAuth2, "alice", false, false);
        byte[] resp2 = sendRadiusPacket(packet2, 1500);
        assertNotNull(resp2, "Expected RADIUS Access-Reject response for second session attempt");
        assertEquals(3, resp2[0] & 0xFF, "Second distinct RADIUS check must receive Access-Reject (Code 3)");
        assertEquals(11, resp2[1] & 0xFF);
        assertValidResponseAuthenticator(resp2, reqAuth2);
    }

    @Test
    public void testTotpAntiReplayRejection() throws Exception {
        User user = createUserWithSecret("replayuser");
        int otp = totpService.generateOtp(user.getSecret());

        mockMvc.perform(post("/v1/api/mfa/preauth")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"replayuser\",\"otp\":" + otp + "}"))
                .andExpect(status().isOk())
                .andExpect(content().string("true"));

        // Reusing the exact same 6-digit TOTP code for the same user in the same window must fail
        MvcResult replayResult = mockMvc.perform(post("/v1/api/mfa/preauth")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"replayuser\",\"otp\":" + otp + "}"))
                .andReturn();

        int status = replayResult.getResponse().getStatus();
        String body = replayResult.getResponse().getContentAsString();
        assertTrue(status == 400 || "false".equalsIgnoreCase(body.trim()),
                "Replayed TOTP code in the same time-step window must be rejected");
    }

    @Test
    public void testActiveDirectoryDomainAndUpnUsernameNormalization() throws Exception {
        User bob = createUserWithSecret("bob");
        int otp = totpService.generateOtp(bob.getSecret());

        // Pre-authenticate using NetBIOS DOMAIN\\username format
        mockMvc.perform(post("/v1/api/mfa/preauth")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"CONTOSO\\\\bob\",\"otp\":" + otp + "}"))
                .andExpect(status().isOk())
                .andExpect(content().string("true"));

        // Query over RADIUS using Active Directory UPN username@domain format
        byte[] reqAuth = randomAuthenticator();
        byte[] packet = buildAccessRequest(21, reqAuth, "bob@contoso.local", false, false);
        byte[] resp = sendRadiusPacket(packet, 1500);

        assertNotNull(resp, "Expected RADIUS response for AD UPN username");
        assertEquals(2, resp[0] & 0xFF, "Expected Access-Accept (Code 2) when matching normalized AD usernames");
        assertEquals(21, resp[1] & 0xFF);
        assertValidResponseAuthenticator(resp, reqAuth);
    }

    @Test
    public void testMessageAuthenticatorAttribute80ValidAndTampered() throws Exception {
        User charlie = createUserWithSecret("charlie");
        int otp = totpService.generateOtp(charlie.getSecret());

        mockMvc.perform(post("/v1/api/mfa/preauth")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"charlie\",\"otp\":" + otp + "}"))
                .andExpect(status().isOk())
                .andExpect(content().string("true"));

        // 1. Send an Access-Request with a tampered Message-Authenticator (Attribute 80)
        byte[] badAuth = randomAuthenticator();
        byte[] badPacket = buildAccessRequest(30, badAuth, "charlie", true, true);
        byte[] badResp = sendRadiusPacket(badPacket, 600);
        if (badResp != null) {
            assertEquals(3, badResp[0] & 0xFF,
                    "Tampered Message-Authenticator must either be silently discarded or return Access-Reject (Code 3)");
        }

        // 2. Send a valid Access-Request with a properly signed Message-Authenticator (Attribute 80)
        // Charlie's pre-auth approval must still be intact and return Access-Accept
        byte[] goodAuth = randomAuthenticator();
        byte[] goodPacket = buildAccessRequest(31, goodAuth, "charlie", true, false);
        byte[] goodResp = sendRadiusPacket(goodPacket, 1500);

        assertNotNull(goodResp, "Expected RADIUS response for valid Message-Authenticator request");
        assertEquals(2, goodResp[0] & 0xFF, "Expected Access-Accept (Code 2) for valid Message-Authenticator");
        assertEquals(31, goodResp[1] & 0xFF);
        assertValidResponseAuthenticator(goodResp, goodAuth);
        assertValidResponseMessageAuthenticatorIfPresent(goodResp, goodAuth);
    }

    @Test
    public void testUnauthenticatedWebPreAuthFlowAndTtlExpiration() throws Exception {
        // Verify GET /mfa is accessible without authentication (no redirect to /login)
        mockMvc.perform(get("/mfa"))
                .andExpect(status().isOk());

        User dave = createUserWithSecret("dave");
        int otp = totpService.generateOtp(dave.getSecret());

        MvcResult postResult = mockMvc.perform(post("/mfa")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("username", "dave")
                        .param("otp", String.valueOf(otp)))
                .andReturn();

        int postStatus = postResult.getResponse().getStatus();
        String redirectedUrl = postResult.getResponse().getRedirectedUrl();
        assertTrue(postStatus == 200 || (postStatus == 302 && (redirectedUrl == null || !redirectedUrl.contains("/login"))),
                "POST /mfa must be permitted without redirecting to /login");

        // Wait for the 3-second TTL to expire
        Thread.sleep(3300);

        byte[] reqAuth = randomAuthenticator();
        byte[] packet = buildAccessRequest(40, reqAuth, "dave", false, false);
        byte[] resp = sendRadiusPacket(packet, 1500);

        assertNotNull(resp, "Expected RADIUS response after TTL expiration");
        assertEquals(3, resp[0] & 0xFF, "Expired pre-authentication approval must return Access-Reject (Code 3)");
        assertValidResponseAuthenticator(resp, reqAuth);
    }

    private byte[] randomAuthenticator() {
        byte[] auth = new byte[16];
        secureRandom.nextBytes(auth);
        return auth;
    }

    private byte[] buildAccessRequest(int identifier, byte[] requestAuthenticator, String username,
                                      boolean includeMessageAuthenticator, boolean tamperMessageAuthenticator) throws Exception {
        byte[] userBytes = username.getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream attrs = new ByteArrayOutputStream();
        // Attribute 1: User-Name
        attrs.write(1);
        attrs.write(2 + userBytes.length);
        attrs.write(userBytes);

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
            assertTrue(len >= 2 && pos + len <= responsePacket.length, "Malformed TLV attribute in RADIUS response");
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
