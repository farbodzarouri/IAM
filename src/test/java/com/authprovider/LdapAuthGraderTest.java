package com.authprovider;

import com.authprovider.entity.User;
import com.authprovider.repository.UserRepository;
import com.authprovider.service.TotpService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = "ldap.fallback-to-local=false")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class LdapAuthGraderTest {

    private static MockLdapServer mockLdapServer;
    private static volatile boolean fallbackToLocal = false;
    private static final ObjectMapper objectMapper = new ObjectMapper();

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TotpService totpService;

    @BeforeAll
    public static void startLdapServer() throws IOException {
        if (mockLdapServer == null) {
            mockLdapServer = new MockLdapServer();
            Runtime.getRuntime().addShutdownHook(new Thread(LdapAuthGraderTest::stopLdapServer));
        }
    }

    public static MockLdapServer getMockLdapServer() {
        return mockLdapServer;
    }

    public static int getMockLdapPort() {
        if (mockLdapServer == null) {
            try {
                mockLdapServer = new MockLdapServer();
                Runtime.getRuntime().addShutdownHook(new Thread(LdapAuthGraderTest::stopLdapServer));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        return mockLdapServer.getPort();
    }

    public static void stopLdapServer() {
        if (mockLdapServer != null) {
            mockLdapServer.close();
            mockLdapServer = null;
        }
    }

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("ldap.enabled", () -> "true");
        registry.add("ldap.url", () -> "ldap://localhost:" + mockLdapServer.getPort());
        registry.add("ldap.base-dn", () -> "dc=example,dc=org");
        registry.add("ldap.user-search-filter", () -> "(&(objectClass=person)(|(uid={0})(sAMAccountName={0})))");
        registry.add("ldap.bind-dn", () -> "cn=admin,dc=example,dc=org");
        registry.add("ldap.bind-password", () -> "secret");
        registry.add("ldap.auto-provision", () -> "true");
        registry.add("ldap.fallback-to-local", () -> String.valueOf(fallbackToLocal));
    }

    @BeforeEach
    public void resetRecordedState() {
        mockLdapServer.resetState();
    }

    @Test
    @Order(1)
    @DisplayName("Initial Login: First-time LDAP user is JIT provisioned and returns enrollment metadata")
    public void testInitialLogin_JitProvisioningAndEnrollmentReturned() throws Exception {
        userRepository.findByUsername("alice").ifPresent(userRepository::delete);
        assertTrue(userRepository.findByUsername("alice").isEmpty());

        Map<String, String> request = Map.of(
                "username", "alice",
                "password", "Password123!"
        );

        MvcResult result = mockMvc.perform(post("/v1/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.secret").isNotEmpty())
                .andExpect(jsonPath("$.otpAuthUri").isNotEmpty())
                .andExpect(jsonPath("$.qrCode").isNotEmpty())
                .andReturn();

        JsonNode responseJson = objectMapper.readTree(result.getResponse().getContentAsString());
        String secret = responseJson.get("secret").asText();
        String otpAuthUri = responseJson.get("otpAuthUri").asText();
        String qrCode = responseJson.get("qrCode").asText();

        // Validate secret is a valid Base32 string
        assertTrue(secret.matches("^[A-Z2-7]{16,32}$"), "Secret must be a valid Base32 string");
        // Validate otpAuthUri format
        assertTrue(otpAuthUri.startsWith("otpauth://totp/"), "URI must begin with otpauth://totp/");
        assertTrue(otpAuthUri.contains("secret=" + secret), "URI must include the generated secret");
        // Validate qrCode is valid Base64 PNG image
        byte[] qrBytes = Base64.getDecoder().decode(qrCode);
        assertTrue(qrBytes.length > 8, "QR code image must contain valid data");
        assertEquals((byte) 0x89, qrBytes[0], "First byte of PNG must be 0x89");
        assertEquals((byte) 'P', qrBytes[1]);
        assertEquals((byte) 'N', qrBytes[2]);
        assertEquals((byte) 'G', qrBytes[3]);

        // Verify database state: user must exist, secret populated, and raw password NEVER stored in plaintext
        Optional<User> savedUserOpt = userRepository.findByUsername("alice");
        assertTrue(savedUserOpt.isPresent(), "JIT user must be saved in database");
        User savedUser = savedUserOpt.get();
        assertEquals(secret, savedUser.getSecret(), "Saved user must have the generated secret");
        assertNotEquals("Password123!", savedUser.getPassword(), "Raw LDAP password must not be stored in plaintext");
    }

    @Test
    @Order(2)
    @DisplayName("Subsequent Login: Valid LDAP password and valid TOTP code succeeds")
    public void testSubsequentLogin_ValidLdapPasswordAndValidTotp_Success() throws Exception {
        User user = userRepository.findByUsername("alice")
                .orElseThrow(() -> new IllegalStateException("Alice should have been provisioned in Test 1"));

        int currentOtp = totpService.generateOtp(user.getSecret());
        String otpStr = String.format("%06d", currentOtp);

        Map<String, String> request = Map.of(
                "username", "alice",
                "password", "Password123!",
                "otp", otpStr
        );

        mockMvc.perform(post("/v1/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());
    }

    @Test
    @Order(3)
    @DisplayName("MFA Short-Circuit: Invalid LDAP password must fail immediately even with valid TOTP")
    public void testMfaShortCircuit_InvalidLdapPassword_FailsImmediately() throws Exception {
        User user = userRepository.findByUsername("alice")
                .orElseThrow(() -> new IllegalStateException("Alice must exist"));

        int currentOtp = totpService.generateOtp(user.getSecret());
        String otpStr = String.format("%06d", currentOtp);

        Map<String, String> request = Map.of(
                "username", "alice",
                "password", "IncorrectPassword123!",
                "otp", otpStr
        );

        mockMvc.perform(post("/v1/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @Order(4)
    @DisplayName("MFA Second-Factor Failure: Valid LDAP password with invalid TOTP code fails")
    public void testMfa_ValidLdapPassword_InvalidTotp_Fails() throws Exception {
        User user = userRepository.findByUsername("alice")
                .orElseThrow(() -> new IllegalStateException("Alice must exist"));

        int currentOtp = totpService.generateOtp(user.getSecret());
        // Pick an invalid OTP code different from the current one
        int invalidOtp = (currentOtp + 123456) % 1000000;
        String invalidOtpStr = String.format("%06d", invalidOtp);

        Map<String, String> request = Map.of(
                "username", "alice",
                "password", "Password123!",
                "otp", invalidOtpStr
        );

        mockMvc.perform(post("/v1/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @Order(5)
    @DisplayName("Security Trap: Empty password must be rejected without performing an anonymous LDAP bind")
    public void testAnonymousBindExploit_EmptyPasswordRejected() throws Exception {
        mockLdapServer.anonymousBindAttempted = false;

        Map<String, String> request = new HashMap<>();
        request.put("username", "alice");
        request.put("password", "");

        mockMvc.perform(post("/v1/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(result -> {
                    int sc = result.getResponse().getStatus();
                    assertTrue(sc == 401 || sc == 400,
                            "Empty password must be rejected with HTTP 401 or HTTP 400, got: " + sc);
                });

        assertFalse(mockLdapServer.anonymousBindAttempted,
                "Authentication provider must reject empty passwords before binding to prevent anonymous bind bypass");
    }

    @Test
    @Order(6)
    @DisplayName("Security Trap: LDAP Filter Injection payload must be sanitized")
    public void testLdapFilterInjection_SpecialCharactersSanitized() throws Exception {
        Map<String, String> request = Map.of(
                "username", "alice*)(|(uid=*))",
                "password", "Password123!"
        );

        mockMvc.perform(post("/v1/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());

        // Verify that the server's search filters did not contain raw unsanitized injection syntax
        assertFalse(mockLdapServer.injectedWildcardFilterReceived,
                "LDAP filter must not evaluate injected wildcards or secondary filter branches");
    }

    @Test
    @Order(7)
    @DisplayName("Fallback Policy (false): Local database user rejected when LDAP is enabled and fallback is disabled")
    public void testFallbackPolicy_False_LocalUserRejected() throws Exception {
        // Create a user in the local DB who does NOT exist in LDAP
        User localUser = userRepository.findByUsername("localadmin")
                .orElseGet(() -> userRepository.save(User.builder()
                        .username("localadmin")
                        .password("LocalAdminSecretPass!")
                        .build()));

        Map<String, String> request = Map.of(
                "username", "localadmin",
                "password", "LocalAdminSecretPass!"
        );

        mockMvc.perform(post("/v1/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @Order(8)
    @DisplayName("Resource Management: Directory connections and sockets cleanly closed under repeated requests")
    public void testDirectoryResourceManagement_ConnectionsClosedUnderLoad() throws Exception {
        User user = userRepository.findByUsername("alice")
                .orElseThrow(() -> new IllegalStateException("Alice must exist"));

        int otp = totpService.generateOtp(user.getSecret());
        String otpStr = String.format("%06d", otp);

        for (int i = 0; i < 10; i++) {
            Map<String, String> request = Map.of(
                    "username", "alice",
                    "password", "Password123!",
                    "otp", otpStr
            );
            mockMvc.perform(post("/v1/api/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk());
        }
    }

    @Test
    @DisplayName("Subsequent MFA Login: Missing OTP field must be rejected with 401")
    public void testSubsequentLogin_MissingOtpField_Fails() throws Exception {
        userRepository.findByUsername("alice")
                .orElseGet(() -> userRepository.save(User.builder()
                        .username("alice")
                        .secret("JBSWY3DPEHPK3PXP")
                        .build()));

        Map<String, String> request = Map.of(
                "username", "alice",
                "password", "Password123!"
        );

        mockMvc.perform(post("/v1/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Non-existent User: User neither in LDAP nor local DB must be rejected with 401")
    public void testNonExistentUser_NeitherInLdapNorLocalDb_Fails() throws Exception {
        Map<String, String> request = Map.of(
                "username", "ghost_user_404",
                "password", "AnyPassword123!",
                "otp", "123456"
        );

        mockMvc.perform(post("/v1/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Input Validation: Blank username or empty request body must be rejected")
    public void testInputValidation_BlankUsernameOrEmptyBody_Rejected() throws Exception {
        Map<String, String> blankUserRequest = Map.of(
                "username", "   ",
                "password", "Password123!"
        );

        mockMvc.perform(post("/v1/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(blankUserRequest)))
                .andExpect(status().is4xxClientError());

        mockMvc.perform(post("/v1/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().is4xxClientError());
    }

    @Test
    @DisplayName("Enterprise Domain Account: DOMAIN\\username returns valid RFC-compliant enrollment URI")
    public void testDomainQualifiedAccount_ReturnsValidRfcCompliantUri() throws Exception {
        userRepository.findByUsername("CORP\\alice").ifPresent(userRepository::delete);

        Map<String, String> request = Map.of(
                "username", "CORP\\alice",
                "password", "Password123!"
        );

        MvcResult result = mockMvc.perform(post("/v1/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andReturn();

        JsonNode json = objectMapper.readTree(result.getResponse().getContentAsString());
        String otpAuthUri = json.path("otpAuthUri").asText();
        assertNotNull(otpAuthUri, "otpAuthUri must not be null");
        assertFalse(otpAuthUri.isBlank(), "otpAuthUri must not be blank");

        // Strict RFC 2396/3986 compliance check: must parse cleanly as a valid URI
        URI parsedUri = assertDoesNotThrow(() -> URI.create(otpAuthUri),
                "otpAuthUri must be a valid, parseable URI for domain accounts");
        assertEquals("otpauth", parsedUri.getScheme());
        assertFalse(otpAuthUri.contains("\\"), "Domain backslash in URI path must be properly URL-encoded");
    }

    /**
     * Pure Java Standard SE Mock LDAP Server (zero external dependencies).
     * Listens on an ephemeral TCP port and responds to LDAPv3 Bind and Search requests.
     */
    public static class MockLdapServer implements AutoCloseable {
        private final ServerSocket serverSocket;
        private final Thread thread;
        private volatile boolean running = true;
        public final List<String> bindRequests = Collections.synchronizedList(new ArrayList<>());
        public final List<String> searchFilters = Collections.synchronizedList(new ArrayList<>());
        public volatile boolean anonymousBindAttempted = false;
        public volatile boolean injectedWildcardFilterReceived = false;

        public MockLdapServer() throws IOException {
            serverSocket = new ServerSocket(0);
            thread = new Thread(this::run);
            thread.setDaemon(true);
            thread.start();
        }

        public int getPort() {
            return serverSocket.getLocalPort();
        }

        public void resetState() {
            bindRequests.clear();
            searchFilters.clear();
            anonymousBindAttempted = false;
            injectedWildcardFilterReceived = false;
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
                    if (tag != 0x30) continue; // SEQUENCE
                    int seqLen = readLength(in);
                    byte[] seqBytes = readBytes(in, seqLen);
                    ByteArrayInputStream bin = new ByteArrayInputStream(seqBytes);

                    // Message ID
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
                        opIn.read(); // version tag
                        int verLen = readLength(opIn);
                        readBytes(opIn, verLen);

                        opIn.read(); // name tag
                        int nameLen = readLength(opIn);
                        String bindDn = new String(readBytes(opIn, nameLen), StandardCharsets.UTF_8);

                        opIn.read(); // auth tag
                        int authLen = readLength(opIn);
                        String pass = new String(readBytes(opIn, authLen), StandardCharsets.UTF_8);

                        bindRequests.add(bindDn + ":" + pass);
                        if (pass.isEmpty()) {
                            if (!bindDn.isEmpty()) {
                                anonymousBindAttempted = true;
                            }
                        }

                        boolean ok = false;
                        if (bindDn.isEmpty() && pass.isEmpty()) {
                            ok = true; // unauthenticated search
                        } else if ("cn=admin,dc=example,dc=org".equals(bindDn) && "secret".equals(pass)) {
                            ok = true;
                        } else if ("uid=alice,ou=users,dc=example,dc=org".equals(bindDn) && "Password123!".equals(pass)) {
                            ok = true;
                        } else if ("uid=bob,ou=users,dc=example,dc=org".equals(bindDn) && "BobLdapPass!".equals(pass)) {
                            ok = true;
                        } else if (bindDn != null && bindDn.toUpperCase(Locale.ROOT).contains("CORP") && "Password123!".equals(pass)) {
                            ok = true;
                        }

                        sendBindResponse(out, messageId, ok ? 0 : 49);
                    } else if (opTag == 0x63) { // SearchRequest
                        opIn.read();
                        int baseLen = readLength(opIn);
                        readBytes(opIn, baseLen);

                        for (int i = 0; i < 5; i++) {
                            opIn.read();
                            int l = readLength(opIn);
                            readBytes(opIn, l);
                        }

                        byte[] remaining = opIn.readAllBytes();
                        for (byte b : remaining) {
                            if (b == (byte) 0x87 || b == (byte) 0xA4) {
                                injectedWildcardFilterReceived = true;
                            }
                        }
                        String filterStr = new String(remaining, StandardCharsets.ISO_8859_1);
                        searchFilters.add(filterStr);

                        String filterUpper = filterStr.toUpperCase(Locale.ROOT);
                        boolean isDomainAlice = filterUpper.contains("CORP\\ALICE") || filterUpper.contains("CORP\\5CALICE");
                        boolean isAlice = filterStr.contains("\u0004\u0005alice") || isDomainAlice;
                        boolean isBob = filterStr.contains("\u0004\u0003bob");

                        if (isDomainAlice) {
                            sendSearchResultEntry(out, messageId, "uid=CORP\\\\alice,ou=users,dc=example,dc=org", "CORP\\alice");
                        } else if (isAlice) {
                            sendSearchResultEntry(out, messageId, "uid=alice,ou=users,dc=example,dc=org", "alice");
                        } else if (isBob) {
                            sendSearchResultEntry(out, messageId, "uid=bob,ou=users,dc=example,dc=org", "bob");
                        }
                        sendSearchResultDone(out, messageId, 0);
                    } else if (opTag == 0x42) { // UnbindRequest
                        break;
                    }
                }
            } catch (Exception ignored) {
            } finally {
                try { socket.close(); } catch (Exception ignored) {}
            }
        }

        private static int readLength(InputStream in) throws IOException {
            int b = in.read();
            if (b == -1) throw new EOFException();
            if ((b & 0x80) == 0) return b;
            int numBytes = b & 0x7F;
            int length = 0;
            for (int i = 0; i < numBytes; i++) {
                int next = in.read();
                if (next == -1) throw new EOFException();
                length = (length << 8) | next;
            }
            return length;
        }

        private static byte[] readBytes(InputStream in, int len) throws IOException {
            byte[] buf = new byte[len];
            int read = 0;
            while (read < len) {
                int n = in.read(buf, read, len - read);
                if (n == -1) throw new EOFException();
                read += n;
            }
            return buf;
        }

        private static void writeLength(ByteArrayOutputStream out, int length) {
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

        private void sendBindResponse(OutputStream out, int messageId, int resultCode) throws IOException {
            ByteArrayOutputStream op = new ByteArrayOutputStream();
            op.write(0x0A); // ENUMERATED resultCode
            op.write(1);
            op.write(resultCode);
            op.write(0x04); // matchedDN
            op.write(0);
            op.write(0x04); // diagnosticMessage
            op.write(0);

            byte[] opBytes = op.toByteArray();
            ByteArrayOutputStream resp = new ByteArrayOutputStream();
            resp.write(0x02); // INTEGER messageId
            resp.write(1);
            resp.write(messageId);
            resp.write(0x61); // BindResponse
            writeLength(resp, opBytes.length);
            resp.write(opBytes);

            byte[] packet = resp.toByteArray();
            ByteArrayOutputStream frame = new ByteArrayOutputStream();
            frame.write(0x30); // SEQUENCE
            writeLength(frame, packet.length);
            frame.write(packet);

            out.write(frame.toByteArray());
            out.flush();
        }

        private void sendSearchResultEntry(OutputStream out, int messageId, String dn, String uid) throws IOException {
            ByteArrayOutputStream entry = new ByteArrayOutputStream();
            byte[] dnBytes = dn.getBytes(StandardCharsets.UTF_8);
            entry.write(0x04);
            writeLength(entry, dnBytes.length);
            entry.write(dnBytes);

            ByteArrayOutputStream attrs = new ByteArrayOutputStream();
            ByteArrayOutputStream attr = new ByteArrayOutputStream();
            byte[] uidType = "uid".getBytes(StandardCharsets.UTF_8);
            attr.write(0x04);
            writeLength(attr, uidType.length);
            attr.write(uidType);

            ByteArrayOutputStream vals = new ByteArrayOutputStream();
            byte[] val = uid.getBytes(StandardCharsets.UTF_8);
            vals.write(0x04);
            writeLength(vals, val.length);
            vals.write(val);

            byte[] valsBytes = vals.toByteArray();
            attr.write(0x31); // SET
            writeLength(attr, valsBytes.length);
            attr.write(valsBytes);

            byte[] attrBytes = attr.toByteArray();
            attrs.write(0x30);
            writeLength(attrs, attrBytes.length);
            attrs.write(attrBytes);

            byte[] attrsBytes = attrs.toByteArray();
            entry.write(0x30);
            writeLength(entry, attrsBytes.length);
            entry.write(attrsBytes);

            byte[] entryBytes = entry.toByteArray();
            ByteArrayOutputStream resp = new ByteArrayOutputStream();
            resp.write(0x02);
            resp.write(1);
            resp.write(messageId);
            resp.write(0x64); // SearchResultEntry
            writeLength(resp, entryBytes.length);
            resp.write(entryBytes);

            byte[] packet = resp.toByteArray();
            ByteArrayOutputStream frame = new ByteArrayOutputStream();
            frame.write(0x30);
            writeLength(frame, packet.length);
            frame.write(packet);

            out.write(frame.toByteArray());
            out.flush();
        }

        private void sendSearchResultDone(OutputStream out, int messageId, int resultCode) throws IOException {
            ByteArrayOutputStream op = new ByteArrayOutputStream();
            op.write(0x0A);
            op.write(1);
            op.write(resultCode);
            op.write(0x04);
            op.write(0);
            op.write(0x04);
            op.write(0);

            byte[] opBytes = op.toByteArray();
            ByteArrayOutputStream resp = new ByteArrayOutputStream();
            resp.write(0x02);
            resp.write(1);
            resp.write(messageId);
            resp.write(0x65); // SearchResultDone
            writeLength(resp, opBytes.length);
            resp.write(opBytes);

            byte[] packet = resp.toByteArray();
            ByteArrayOutputStream frame = new ByteArrayOutputStream();
            frame.write(0x30);
            writeLength(frame, packet.length);
            frame.write(packet);

            out.write(frame.toByteArray());
            out.flush();
        }

        @Override
        public void close() {
            running = false;
            try { serverSocket.close(); } catch (Exception ignored) {}
        }
    }
}
