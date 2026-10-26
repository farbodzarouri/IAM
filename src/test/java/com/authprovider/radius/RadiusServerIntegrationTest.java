package com.authprovider.radius;

import com.authprovider.entity.User;
import com.authprovider.repository.UserRepository;
import com.authprovider.service.TotpServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {"radius.port=0", "radius.shared-secret=testing123", "radius.mfa.ttl-seconds=60"})
@AutoConfigureMockMvc
class RadiusServerIntegrationTest {

    private static final byte[] SECRET = "testing123".getBytes(StandardCharsets.UTF_8);
    private static final SecureRandom RANDOM = new SecureRandom();

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private RadiusServer radiusServer;
    @Autowired
    private UserRepository userRepository;

    private final TotpServiceImpl totp = new TotpServiceImpl();
    private User user;

    @BeforeEach
    void setUp() {
        String name = "rdguser" + RANDOM.nextInt(1_000_000);
        user = userRepository.save(User.builder().username(name).secret("JBSWY3DPEHPK3PXP").build());
    }

    private String preauthJson(String username, int otp) {
        return "{\"username\":\"" + username.replace("\\", "\\\\") + "\",\"otp\":" + otp + "}";
    }

    private void preauth(String username) throws Exception {
        mockMvc.perform(post("/v1/api/mfa/preauth").contentType(MediaType.APPLICATION_JSON)
                        .content(preauthJson(username, totp.generateOtp(user.getSecret()))))
                .andExpect(status().isOk()).andExpect(content().string("true"));
    }

    private static byte[] randomAuth() {
        byte[] a = new byte[16];
        RANDOM.nextBytes(a);
        return a;
    }

    private static byte[] request(int id, byte[] auth, String userName, boolean withMa, byte[]... proxyStates) {
        List<RadiusPacket.Attribute> attrs = new ArrayList<>();
        attrs.add(new RadiusPacket.Attribute(RadiusPacket.ATTR_USER_NAME, userName.getBytes(StandardCharsets.UTF_8)));
        attrs.add(new RadiusPacket.Attribute(32, "RDG-NPS".getBytes(StandardCharsets.UTF_8)));
        for (byte[] ps : proxyStates) {
            attrs.add(new RadiusPacket.Attribute(RadiusPacket.ATTR_PROXY_STATE, ps));
        }
        return RadiusPacket.encodeAccessRequest(id, auth, attrs, SECRET, withMa);
    }

    private byte[] send(DatagramSocket socket, byte[] packet) throws Exception {
        socket.send(new DatagramPacket(packet, packet.length, InetAddress.getLoopbackAddress(), radiusServer.getLocalPort()));
        byte[] buf = new byte[4096];
        DatagramPacket resp = new DatagramPacket(buf, buf.length);
        try {
            socket.receive(resp);
        } catch (SocketTimeoutException e) {
            return null;
        }
        return Arrays.copyOf(buf, resp.getLength());
    }

    private static DatagramSocket client() throws Exception {
        DatagramSocket s = new DatagramSocket();
        s.setSoTimeout(1500);
        return s;
    }

    @Test
    void mfaFormIsPublic() throws Exception {
        mockMvc.perform(get("/mfa")).andExpect(status().isOk());
        mockMvc.perform(post("/mfa").param("username", user.getUsername())
                        .param("otp", String.format("%06d", totp.generateOtp(user.getSecret()))))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("MFA approved")));
        try (DatagramSocket s = client()) {
            byte[] auth = randomAuth();
            byte[] resp = send(s, request(1, auth, user.getUsername(), true));
            assertEquals(RadiusPacket.ACCESS_ACCEPT, resp[0] & 0xff);
        }
    }

    @Test
    void acceptOnceThenRejectAndRetransmissionGetsSameReply() throws Exception {
        preauth(user.getUsername());
        try (DatagramSocket s = client()) {
            byte[] auth = randomAuth();
            byte[] proxyState = {1, 2, 3, 4};
            byte[] req = request(7, auth, "CORP\\" + user.getUsername().toUpperCase(), true, proxyState);
            byte[] resp = send(s, req);
            assertNotNull(resp);
            assertEquals(RadiusPacket.ACCESS_ACCEPT, resp[0] & 0xff);
            assertEquals(7, resp[1] & 0xff);
            assertTrue(RadiusPacket.verifyResponse(resp, resp.length, auth, SECRET));
            RadiusPacket decoded = RadiusPacket.decode(resp, 0, resp.length);
            assertArrayEquals(proxyState, decoded.getAttribute(RadiusPacket.ATTR_PROXY_STATE).value());
            assertTrue(decoded.hasMessageAuthenticator());

            // retransmission: same reply, approval not re-evaluated
            byte[] again = send(s, req);
            assertArrayEquals(resp, again);

            // new request: approval already consumed
            byte[] auth2 = randomAuth();
            byte[] resp2 = send(s, request(8, auth2, user.getUsername(), true));
            assertEquals(RadiusPacket.ACCESS_REJECT, resp2[0] & 0xff);
            assertTrue(RadiusPacket.verifyResponse(resp2, resp2.length, auth2, SECRET));
        }
    }

    @Test
    void rejectWithoutApprovalAndDiscardInvalidPackets() throws Exception {
        try (DatagramSocket s = client()) {
            byte[] resp = send(s, request(1, randomAuth(), user.getUsername(), true));
            assertEquals(RadiusPacket.ACCESS_REJECT, resp[0] & 0xff);
        }
        preauth(user.getUsername());
        try (DatagramSocket s = client()) {
            byte[] tampered = request(2, randomAuth(), user.getUsername(), true); tampered[tampered.length - 1] ^= 0x5A; assertNull(send(s, tampered));
            // wrong secret -> silently discarded
            byte[] bad = RadiusPacket.encodeAccessRequest(3, randomAuth(), List.of(new RadiusPacket.Attribute(
                    1, user.getUsername().getBytes(StandardCharsets.UTF_8))), "wrong".getBytes(), true);
            assertNull(send(s, bad));
            // garbage
            assertNull(send(s, new byte[]{1, 2, 0, 5}));
            // the approval is still intact
            byte[] resp = send(s, request(4, randomAuth(), user.getUsername() + "@corp.example.com", true));
            assertEquals(RadiusPacket.ACCESS_ACCEPT, resp[0] & 0xff);
        }
    }

    @Test
    void replayWithDifferentIdIsDiscarded() throws Exception {
        preauth(user.getUsername());
        byte[] auth = randomAuth();
        byte[] req = request(9, auth, user.getUsername(), true);
        try (DatagramSocket s = client()) {
            assertEquals(RadiusPacket.ACCESS_ACCEPT, send(s, req)[0] & 0xff);
        }
        try (DatagramSocket s2 = client()) {
            assertEquals(RadiusPacket.ACCESS_ACCEPT, send(s2, req)[0] & 0xff);
        }
        byte[] replay = request(10, auth, user.getUsername(), true);
        try (DatagramSocket s3 = client()) {
            assertNull(send(s3, replay));
        }
    }

    @Test
    void otpCannotBeReused() throws Exception {
        int otp = totp.generateOtp(user.getSecret());
        mockMvc.perform(post("/v1/api/mfa/preauth").contentType(MediaType.APPLICATION_JSON)
                .content(preauthJson(user.getUsername(), otp))).andExpect(content().string("true"));
        mockMvc.perform(post("/v1/api/mfa/preauth").contentType(MediaType.APPLICATION_JSON)
                .content(preauthJson(user.getUsername(), otp))).andExpect(content().string("false"));
    }

    @Test
    void preauthValidation() throws Exception {
        mockMvc.perform(post("/v1/api/mfa/preauth").contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isBadRequest()).andExpect(content().string("false"));
        mockMvc.perform(post("/v1/api/mfa/preauth").contentType(MediaType.APPLICATION_JSON).content("not json"))
                .andExpect(status().isBadRequest());
        mockMvc.perform(post("/v1/api/mfa/preauth").contentType(MediaType.APPLICATION_JSON)
                        .content(preauthJson("nobody-here", 123456)))
                .andExpect(status().isOk()).andExpect(content().string("false"));
    }
}
