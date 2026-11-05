package com.authprovider;

import com.authprovider.entity.User;
import com.authprovider.repository.UserRepository;
import com.authprovider.service.SecretGenerator;
import com.authprovider.service.TotpService;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(properties = {
        "radius.port=18128",
        "radius.shared-secret=testing123",
        "radius.shared.secret=testing123",
        "radius.challenge.ttl-seconds=10",
        "ldap.enabled=true",
        "ldap.base-dn=dc=example,dc=org",
        "ldap.user-search-filter=(&(objectClass=person)(|(uid={0})(sAMAccountName={0})))",
        "ldap.fallback-to-local=false"
})
public class RadiusLdapFederationTest {

    private static final int RADIUS_PORT = 18128;
    private static final String SHARED_SECRET = "testing123";

    private static MockLdapServer mockLdapServer;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private SecretGenerator secretGenerator;

    @Autowired
    private TotpService totpService;

    private final SecureRandom secureRandom = new SecureRandom();
    private User enrolledBob;

    @BeforeAll
    public static void startLdapServer() throws IOException {
        if (mockLdapServer == null) {
            mockLdapServer = new MockLdapServer();
        }
    }

    @AfterAll
    public static void stopLdapServer() {
        if (mockLdapServer != null) {
            mockLdapServer.close();
            mockLdapServer = null;
        }
    }

    @DynamicPropertySource
    public static void configureLdap(DynamicPropertyRegistry registry) {
        registry.add("ldap.url", () -> "ldap://localhost:" + mockLdapServer.getPort());
    }

    @BeforeEach
    public void setUp() {
        userRepository.deleteAll();

        // bob is in LDAP (BobLdapPass!) and is ENROLLED locally with an OTP secret
        enrolledBob = User.builder()
                .username("bob")
                .password("LocalBobHashPass123!")
                .secret(secretGenerator.generateSecret())
                .build();
        userRepository.save(enrolledBob);

        // alice is in LDAP (Password123!) but is UNENROLLED (not in local DB)
    }

    @Test
    public void testUnenrolledDirectoryUser_RejectedWithEnrollmentRequired() throws Exception {
        byte[] reqAuth = randomAuthenticator();
        byte[] packet = buildAccessRequest(10, reqAuth, "alice", "Password123!", null);
        byte[] resp = sendRadiusPacket(packet, 3000);

        assertNotNull(resp, "Server must respond to unenrolled directory user");
        assertEquals(3, resp[0] & 0xFF, "Unenrolled directory user must be rejected with Access-Reject (Code 3)");
        assertValidResponseAuthenticator(resp, reqAuth);

        byte[] replyMsg = extractAttribute(resp, 18);
        assertNotNull(replyMsg, "Access-Reject must contain Reply-Message (Type 18) indicating MFA enrollment requirement");
        String message = new String(replyMsg, StandardCharsets.UTF_8).toLowerCase(Locale.ROOT);
        assertTrue(message.contains("enroll") || message.contains("mfa") || message.contains("portal") || message.contains("web"),
                "Reply message should inform user of MFA enrollment requirement, but got: " + message);
    }

    @Test
    public void testEnrolledDirectoryUser_HappyPathTwoStepChallengeResponse() throws Exception {
        // Step 1: Access-Request with directory password -> Access-Challenge
        byte[] reqAuth1 = randomAuthenticator();
        byte[] packet1 = buildAccessRequest(20, reqAuth1, "bob", "BobLdapPass!", null);
        byte[] resp1 = sendRadiusPacket(packet1, 3000);

        assertNotNull(resp1, "Server must respond to enrolled directory user primary authentication");
        assertEquals(11, resp1[0] & 0xFF, "Enrolled directory user must receive Access-Challenge (Code 11)");
        assertValidResponseAuthenticator(resp1, reqAuth1);

        byte[] state = extractAttribute(resp1, 24);
        assertNotNull(state, "Access-Challenge must include State attribute (Type 24)");
        assertTrue(state.length > 0, "State attribute must not be empty");

        // Step 2: Access-Request with TOTP + State -> Access-Accept
        String validOtp = String.format("%06d", totpService.generateOtp(enrolledBob.getSecret()));
        byte[] reqAuth2 = randomAuthenticator();
        byte[] packet2 = buildAccessRequest(21, reqAuth2, "bob", validOtp, state);
        byte[] resp2 = sendRadiusPacket(packet2, 3000);

        assertNotNull(resp2, "Server must respond to OTP challenge response");
        assertEquals(2, resp2[0] & 0xFF, "Valid OTP and State must return Access-Accept (Code 2)");
        assertValidResponseAuthenticator(resp2, reqAuth2);
    }

    @Test
    public void testEnrolledDirectoryUser_WrongPassword_ReturnsAccessReject() throws Exception {
        byte[] reqAuth = randomAuthenticator();
        byte[] packet = buildAccessRequest(30, reqAuth, "bob", "WrongLdapPassword!", null);
        byte[] resp = sendRadiusPacket(packet, 3000);

        assertNotNull(resp, "Server must respond to invalid directory credentials");
        assertEquals(3, resp[0] & 0xFF, "Invalid directory password must return Access-Reject (Code 3)");
        assertValidResponseAuthenticator(resp, reqAuth);
    }

    @Test
    public void testEnrolledDirectoryUser_WrongOtp_ReturnsAccessReject() throws Exception {
        // Step 1: Access-Request with directory password
        byte[] reqAuth1 = randomAuthenticator();
        byte[] packet1 = buildAccessRequest(40, reqAuth1, "bob", "BobLdapPass!", null);
        byte[] resp1 = sendRadiusPacket(packet1, 3000);

        assertNotNull(resp1);
        assertEquals(11, resp1[0] & 0xFF);
        byte[] state = extractAttribute(resp1, 24);
        assertNotNull(state);

        // Step 2: Access-Request with bad OTP -> Access-Reject
        byte[] reqAuth2 = randomAuthenticator();
        byte[] packet2 = buildAccessRequest(41, reqAuth2, "bob", "000000", state);
        byte[] resp2 = sendRadiusPacket(packet2, 3000);

        assertNotNull(resp2);
        assertEquals(3, resp2[0] & 0xFF, "Invalid OTP must return Access-Reject (Code 3)");
        assertValidResponseAuthenticator(resp2, reqAuth2);
    }

    @Test
    public void testSecurityBoundary_DirectoryUser_NeverFallsBackToLocalPassword() throws Exception {
        // bob exists in LDAP with "BobLdapPass!" and in DB with "LocalBobHashPass123!"
        // Supplying the local DB password must FAIL because directory credentials take precedence
        // and fallback-to-local is false.
        byte[] reqAuth = randomAuthenticator();
        byte[] packet = buildAccessRequest(50, reqAuth, "bob", "LocalBobHashPass123!", null);
        byte[] resp = sendRadiusPacket(packet, 3000);

        assertNotNull(resp, "Server must respond");
        assertEquals(3, resp[0] & 0xFF, "Directory user must not authenticate with local DB password when fallback is false");
        assertValidResponseAuthenticator(resp, reqAuth);
    }

    @Test
    public void testMixedCaseUsername_EnrolledDirectoryUser_Succeeds() throws Exception {
        byte[] reqAuth = randomAuthenticator();
        byte[] packet = buildAccessRequest(60, reqAuth, "BoB", "BobLdapPass!", null);
        byte[] resp = sendRadiusPacket(packet, 3000);

        assertNotNull(resp, "Server must respond to mixed-case username");
        assertEquals(11, resp[0] & 0xFF, "Case-insensitive directory username must receive Access-Challenge");
        assertValidResponseAuthenticator(resp, reqAuth);
    }

    @Test
    public void testLdapBindThrottling_MaximumSingleBindPerPacket_PreventsAccountLockout() throws Exception {
        // Active Directory lockout policy protection: a single bad password attempt
        // must never issue multiple failed bind attempts (e.g. testing username permutations in a loop).
        mockLdapServer.bindRequests.clear();

        byte[] reqAuth1 = randomAuthenticator();
        byte[] packet1 = buildAccessRequest(70, reqAuth1, "bob", "BadPasswordAttempt!", null);
        byte[] resp1 = sendRadiusPacket(packet1, 3000);

        assertNotNull(resp1, "Server must respond to invalid password attempt");
        assertEquals(3, resp1[0] & 0xFF, "Invalid directory credentials must yield Access-Reject");
        
        // 1 search bind (anonymous or admin) + exactly 1 user authentication bind attempt
        long userBinds1 = mockLdapServer.bindRequests.stream()
                .filter(b -> !b.startsWith(":") && !b.startsWith("cn=admin,"))
                .count();
        assertEquals(1, userBinds1,
                "Server must perform at most 1 user authentication bind per RADIUS packet to prevent domain account lockouts");
        assertEquals(2, mockLdapServer.bindRequests.size(),
                "Server must perform exactly 1 search bind and 1 user authentication bind");

        // Also verify with domain-qualified username: CONTOSO\bob
        mockLdapServer.bindRequests.clear();
        byte[] reqAuth2 = randomAuthenticator();
        byte[] packet2 = buildAccessRequest(71, reqAuth2, "CONTOSO\\bob", "AnotherBadPassword!", null);
        byte[] resp2 = sendRadiusPacket(packet2, 3000);

        assertNotNull(resp2, "Server must respond to invalid domain user attempt");
        assertEquals(3, resp2[0] & 0xFF, "Invalid domain credentials must yield Access-Reject");
        
        long userBinds2 = mockLdapServer.bindRequests.stream()
                .filter(b -> !b.startsWith(":") && !b.startsWith("cn=admin,"))
                .count();
        assertEquals(1, userBinds2,
                "Server must normalize domain prefix and perform at most 1 user bind without looping over variants");
        assertEquals(2, mockLdapServer.bindRequests.size());
    }

    @Test
    public void testDomainStripping_EnrolledDirectoryUser_SucceedsWithSingleBind() throws Exception {
        mockLdapServer.bindRequests.clear();

        byte[] reqAuth = randomAuthenticator();
        byte[] packet = buildAccessRequest(80, reqAuth, "EXAMPLE\\bob", "BobLdapPass!", null);
        byte[] resp = sendRadiusPacket(packet, 3000);

        assertNotNull(resp, "Server must respond to domain-qualified user");
        assertEquals(11, resp[0] & 0xFF, "Domain user with valid credentials must receive Access-Challenge");
        assertValidResponseAuthenticator(resp, reqAuth);
        
        long userBinds = mockLdapServer.bindRequests.stream()
                .filter(b -> !b.startsWith(":") && !b.startsWith("cn=admin,"))
                .count();
        assertEquals(1, userBinds,
                "Domain-qualified authentication must trigger exactly 1 user bind to the directory");
        assertEquals(2, mockLdapServer.bindRequests.size(),
                "Expected 1 search bind + 1 user bind");
    }

    @Test
    public void testMalformedRadiusPacket_DroppedWithoutAffectingDirectory() throws Exception {
        mockLdapServer.bindRequests.clear();

        // Construct malformed packet: length header claims 100 bytes, but datagram is only 22 bytes
        byte[] malformed = new byte[22];
        malformed[0] = 1; // Access-Request
        malformed[1] = (byte) 99;
        malformed[2] = 0;
        malformed[3] = 100; // invalid length > datagram length
        System.arraycopy(randomAuthenticator(), 0, malformed, 4, 16);

        byte[] resp = sendRadiusPacket(malformed, 1000);
        assertNull(resp, "Malformed RADIUS packet must be silently discarded without response");
        assertEquals(0, mockLdapServer.bindRequests.size(),
                "Malformed packet must be dropped before initiating any directory binds");

        // Verify server remains fully functional after malformed packet
        byte[] reqAuth = randomAuthenticator();
        byte[] validPacket = buildAccessRequest(100, reqAuth, "bob", "BobLdapPass!", null);
        byte[] validResp = sendRadiusPacket(validPacket, 3000);
        assertNotNull(validResp, "Server worker pool must remain healthy and process subsequent valid requests");
        assertEquals(11, validResp[0] & 0xFF);
    }

    // =========================================================================
    // RADIUS Packet Helpers
    // =========================================================================

    private byte[] buildAccessRequest(int id, byte[] reqAuth, String username, String password, byte[] state) throws Exception {
        ByteArrayOutputStream attrs = new ByteArrayOutputStream();

        if (username != null) {
            byte[] val = username.getBytes(StandardCharsets.UTF_8);
            attrs.write(1); // User-Name
            attrs.write(val.length + 2);
            attrs.write(val);
        }

        if (password != null) {
            byte[] enc = encryptUserPassword(password.getBytes(StandardCharsets.UTF_8), reqAuth, SHARED_SECRET);
            attrs.write(2); // User-Password
            attrs.write(enc.length + 2);
            attrs.write(enc);
        }

        if (state != null) {
            attrs.write(24); // State
            attrs.write(state.length + 2);
            attrs.write(state);
        }

        byte[] attrBytes = attrs.toByteArray();
        int totalLen = 20 + attrBytes.length;

        ByteBuffer buf = ByteBuffer.allocate(totalLen);
        buf.put((byte) 1); // Access-Request
        buf.put((byte) id);
        buf.putShort((short) totalLen);
        buf.put(reqAuth);
        buf.put(attrBytes);

        return buf.array();
    }

    private byte[] encryptUserPassword(byte[] password, byte[] requestAuth, String secret) throws Exception {
        int paddedLen = ((password.length + 15) / 16) * 16;
        if (paddedLen == 0) paddedLen = 16;
        byte[] padded = new byte[paddedLen];
        System.arraycopy(password, 0, padded, 0, password.length);

        MessageDigest md5 = MessageDigest.getInstance("MD5");
        byte[] secretBytes = secret.getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = new byte[paddedLen];
        byte[] prev = requestAuth;

        for (int i = 0; i < paddedLen; i += 16) {
            md5.reset();
            md5.update(secretBytes);
            md5.update(prev);
            byte[] b = md5.digest();
            for (int j = 0; j < 16; j++) {
                encrypted[i + j] = (byte) (padded[i + j] ^ b[j]);
            }
            prev = Arrays.copyOfRange(encrypted, i, i + 16);
        }
        return encrypted;
    }

    private byte[] randomAuthenticator() {
        byte[] auth = new byte[16];
        secureRandom.nextBytes(auth);
        return auth;
    }

    private byte[] sendRadiusPacket(byte[] requestBytes, int timeoutMs) throws IOException {
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(timeoutMs);
            DatagramPacket req = new DatagramPacket(
                    requestBytes, requestBytes.length, InetAddress.getByName("127.0.0.1"), RADIUS_PORT);
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

    private byte[] extractAttribute(byte[] packet, int type) {
        if (packet.length < 20) return null;
        int len = ((packet[2] & 0xFF) << 8) | (packet[3] & 0xFF);
        int idx = 20;
        while (idx < len && idx < packet.length) {
            int attrType = packet[idx] & 0xFF;
            int attrLen = packet[idx + 1] & 0xFF;
            if (attrLen < 2) break;
            if (attrType == type) {
                byte[] val = new byte[attrLen - 2];
                System.arraycopy(packet, idx + 2, val, 0, val.length);
                return val;
            }
            idx += attrLen;
        }
        return null;
    }

    private void assertValidResponseAuthenticator(byte[] response, byte[] requestAuth) throws Exception {
        assertTrue(response.length >= 20, "Response packet must be at least 20 bytes");
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        md5.update(response[0]); // code
        md5.update(response[1]); // id
        md5.update(response[2]); // len high
        md5.update(response[3]); // len low
        md5.update(requestAuth);
        if (response.length > 20) {
            md5.update(response, 20, response.length - 20);
        }
        md5.update(SHARED_SECRET.getBytes(StandardCharsets.UTF_8));
        byte[] expected = md5.digest();

        byte[] actual = Arrays.copyOfRange(response, 4, 20);
        assertArrayEquals(expected, actual, "Response Authenticator (MD5) must be valid per RFC 2865");
    }

    // =========================================================================
    // Lightweight Mock LDAP Server
    // =========================================================================

    public static class MockLdapServer implements AutoCloseable {
        private final ServerSocket serverSocket;
        private final Thread thread;
        private volatile boolean running = true;
        public final List<String> bindRequests = Collections.synchronizedList(new ArrayList<>());

        public MockLdapServer() throws IOException {
            serverSocket = new ServerSocket(0);
            thread = new Thread(this::run);
            thread.setDaemon(true);
            thread.start();
        }

        public int getPort() {
            return serverSocket.getLocalPort();
        }

        private void run() {
            while (running) {
                try {
                    Socket socket = serverSocket.accept();
                    new Thread(() -> handleClient(socket)).start();
                } catch (IOException e) {
                    break;
                }
            }
        }

        private void handleClient(Socket socket) {
            try (InputStream in = socket.getInputStream();
                 OutputStream out = socket.getOutputStream()) {
                while (running) {
                    int tag = in.read();
                    if (tag == -1) break;
                    if (tag != 0x30) continue;
                    int seqLen = readLength(in);
                    byte[] seqBytes = readBytes(in, seqLen);
                    ByteArrayInputStream bin = new ByteArrayInputStream(seqBytes);

                    bin.read();
                    int idLen = readLength(bin);
                    byte[] idBytes = readBytes(bin, idLen);
                    int messageId = 0;
                    for (byte b : idBytes) {
                        messageId = (messageId << 8) | (b & 0xFF);
                    }

                    int opTag = bin.read();
                    int opLen = readLength(bin);
                    byte[] opBytes = readBytes(bin, opLen);
                    ByteArrayInputStream opIn = new ByteArrayInputStream(opBytes);

                    if (opTag == 0x60) { // BindRequest
                        opIn.read();
                        int verLen = readLength(opIn);
                        readBytes(opIn, verLen);

                        opIn.read();
                        int nameLen = readLength(opIn);
                        String bindDn = new String(readBytes(opIn, nameLen), StandardCharsets.UTF_8);

                        opIn.read();
                        int authLen = readLength(opIn);
                        String pass = new String(readBytes(opIn, authLen), StandardCharsets.UTF_8);

                        bindRequests.add(bindDn + ":" + pass);

                        boolean ok = false;
                        if (bindDn.isEmpty() && pass.isEmpty()) {
                            ok = true;
                        } else if ("cn=admin,dc=example,dc=org".equals(bindDn) && "secret".equals(pass)) {
                            ok = true;
                        } else if ("uid=alice,ou=users,dc=example,dc=org".equals(bindDn) && "Password123!".equals(pass)) {
                            ok = true;
                        } else if ("uid=bob,ou=users,dc=example,dc=org".equals(bindDn) && "BobLdapPass!".equals(pass)) {
                            ok = true;
                        }

                        sendBindResponse(out, messageId, ok ? 0 : 49);
                    } else if (opTag == 0x63) { // SearchRequest
                        opIn.read();
                        int baseLen = readLength(opIn);
                        String baseDn = new String(readBytes(opIn, baseLen), StandardCharsets.UTF_8);

                        for (int i = 0; i < 5; i++) {
                            opIn.read();
                            int l = readLength(opIn);
                            readBytes(opIn, l);
                        }

                        byte[] filterBytes = readRemaining(opIn);
                        String filterStr = new String(filterBytes, StandardCharsets.UTF_8);

                        if (filterStr.toLowerCase(Locale.ROOT).contains("alice")) {
                            sendSearchResultEntry(out, messageId, "uid=alice,ou=users,dc=example,dc=org", "alice");
                        } else if (filterStr.toLowerCase(Locale.ROOT).contains("bob")) {
                            sendSearchResultEntry(out, messageId, "uid=bob,ou=users,dc=example,dc=org", "bob");
                        }
                        sendSearchResultDone(out, messageId, 0);
                    } else if (opTag == 0x42) { // UnbindRequest
                        break;
                    }
                }
            } catch (IOException ignored) {
            }
        }

        private void sendBindResponse(OutputStream out, int messageId, int resultCode) throws IOException {
            ByteArrayOutputStream res = new ByteArrayOutputStream();
            res.write(0x0A); res.write(1); res.write(resultCode); // resultCode
            res.write(0x04); res.write(0); // matchedDN
            res.write(0x04); res.write(0); // errorMessage
            sendLdapMessage(out, messageId, 0x61, res.toByteArray());
        }

        private void sendSearchResultEntry(OutputStream out, int messageId, String dn, String uid) throws IOException {
            ByteArrayOutputStream res = new ByteArrayOutputStream();
            byte[] dnBytes = dn.getBytes(StandardCharsets.UTF_8);
            res.write(0x04);
            writeLength(res, dnBytes.length);
            res.write(dnBytes);

            ByteArrayOutputStream attrs = new ByteArrayOutputStream();
            writeAttribute(attrs, "uid", uid);
            writeAttribute(attrs, "cn", uid);
            writeAttribute(attrs, "mail", uid + "@example.org");

            byte[] attrBytes = attrs.toByteArray();
            res.write(0x30);
            writeLength(res, attrBytes.length);
            res.write(attrBytes);

            sendLdapMessage(out, messageId, 0x64, res.toByteArray());
        }

        private void writeAttribute(ByteArrayOutputStream out, String type, String value) throws IOException {
            ByteArrayOutputStream attr = new ByteArrayOutputStream();
            byte[] typeBytes = type.getBytes(StandardCharsets.UTF_8);
            attr.write(0x04);
            writeLength(attr, typeBytes.length);
            attr.write(typeBytes);

            ByteArrayOutputStream vals = new ByteArrayOutputStream();
            byte[] valBytes = value.getBytes(StandardCharsets.UTF_8);
            vals.write(0x04);
            writeLength(vals, valBytes.length);
            vals.write(valBytes);

            byte[] valsBytes = vals.toByteArray();
            attr.write(0x31); // SET OF
            writeLength(attr, valsBytes.length);
            attr.write(valsBytes);

            byte[] attrBytes = attr.toByteArray();
            out.write(0x30); // SEQUENCE
            writeLength(out, attrBytes.length);
            out.write(attrBytes);
        }

        private void sendSearchResultDone(OutputStream out, int messageId, int resultCode) throws IOException {
            ByteArrayOutputStream res = new ByteArrayOutputStream();
            res.write(0x0A); res.write(1); res.write(resultCode);
            res.write(0x04); res.write(0);
            res.write(0x04); res.write(0);
            sendLdapMessage(out, messageId, 0x65, res.toByteArray());
        }

        private void sendLdapMessage(OutputStream out, int messageId, int protocolOpTag, byte[] protocolOpBytes) throws IOException {
            ByteArrayOutputStream msg = new ByteArrayOutputStream();
            msg.write(0x02); // INTEGER
            msg.write(1);
            msg.write(messageId);

            msg.write(protocolOpTag);
            writeLength(msg, protocolOpBytes.length);
            msg.write(protocolOpBytes);

            byte[] msgBytes = msg.toByteArray();
            out.write(0x30); // SEQUENCE
            writeLength(out, msgBytes.length);
            out.write(msgBytes);
            out.flush();
        }

        private int readLength(InputStream in) throws IOException {
            int b = in.read();
            if (b == -1) throw new EOFException();
            if ((b & 0x80) == 0) return b;
            int numBytes = b & 0x7F;
            int len = 0;
            for (int i = 0; i < numBytes; i++) {
                int next = in.read();
                if (next == -1) throw new EOFException();
                len = (len << 8) | next;
            }
            return len;
        }

        private void writeLength(OutputStream out, int length) throws IOException {
            if (length < 128) {
                out.write(length);
            } else if (length < 256) {
                out.write(0x81);
                out.write(length);
            } else {
                out.write(0x82);
                out.write((length >> 8) & 0xFF);
                out.write(length & 0xFF);
            }
        }

        private byte[] readBytes(InputStream in, int length) throws IOException {
            byte[] bytes = new byte[length];
            int read = 0;
            while (read < length) {
                int r = in.read(bytes, read, length - read);
                if (r == -1) throw new EOFException();
                read += r;
            }
            return bytes;
        }

        private byte[] readRemaining(InputStream in) throws IOException {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buf = new byte[128];
            int r;
            while ((r = in.read(buf)) != -1) {
                baos.write(buf, 0, r);
            }
            return baos.toByteArray();
        }

        @Override
        public void close() {
            running = false;
            try {
                serverSocket.close();
            } catch (IOException ignored) {
            }
        }
    }
}
