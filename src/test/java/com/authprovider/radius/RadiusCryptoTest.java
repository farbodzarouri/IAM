package com.authprovider.radius;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.List;

import static com.authprovider.radius.RadiusConstants.*;
import static org.junit.jupiter.api.Assertions.*;

class RadiusCryptoTest {

    private static final byte[] SECRET = "xyzzy5461".getBytes(StandardCharsets.UTF_8);
    private static final HexFormat HEX = HexFormat.of();

    @Test
    void userPasswordMatchesRfc2865Example() throws Exception {
        byte[] authenticator = HEX.parseHex("0f403f9473978057bd83d5cb98f4227a");
        byte[] encrypted = RadiusCrypto.encryptUserPassword("arctangent".getBytes(StandardCharsets.UTF_8), SECRET, authenticator);
        assertEquals("0dbe708d93d413ce3196e43f782a0aee", HEX.formatHex(encrypted));
        byte[] decrypted = RadiusCrypto.decryptUserPassword(encrypted, SECRET, authenticator);
        assertEquals("arctangent", new String(decrypted, StandardCharsets.UTF_8));
    }

    @Test
    void userPasswordRoundTripsMultipleBlocks() throws Exception {
        byte[] authenticator = new byte[16];
        String password = "a-much-longer-password-spanning-several-blocks-0123456789";
        byte[] encrypted = RadiusCrypto.encryptUserPassword(password.getBytes(StandardCharsets.UTF_8), SECRET, authenticator);
        assertEquals(64, encrypted.length);
        assertEquals(password, new String(RadiusCrypto.decryptUserPassword(encrypted, SECRET, authenticator), StandardCharsets.UTF_8));
    }

    @Test
    void userPasswordRejectsInvalidLengths() {
        assertThrows(RadiusException.class, () -> RadiusCrypto.decryptUserPassword(new byte[15], SECRET, new byte[16]));
        assertThrows(RadiusException.class, () -> RadiusCrypto.decryptUserPassword(new byte[17], SECRET, new byte[16]));
        assertThrows(RadiusException.class, () -> RadiusCrypto.decryptUserPassword(new byte[144], SECRET, new byte[16]));
    }

    @Test
    void requestMessageAuthenticatorIsVerifiedAndDetectsTampering() throws Exception {
        byte[] authenticator = HEX.parseHex("00112233445566778899aabbccddeeff");
        byte[] request = RadiusCrypto.buildRequest(ACCESS_REQUEST, 7, authenticator,
                List.of(RadiusAttribute.ofString(ATTR_USER_NAME, "alice")), SECRET, true);

        assertTrue(RadiusCrypto.verifyRequestMessageAuthenticator(RadiusPacket.decode(request, request.length), SECRET));
        assertFalse(RadiusCrypto.verifyRequestMessageAuthenticator(RadiusPacket.decode(request, request.length),
                "other".getBytes(StandardCharsets.UTF_8)));

        request[request.length - 1] ^= 1;
        assertFalse(RadiusCrypto.verifyRequestMessageAuthenticator(RadiusPacket.decode(request, request.length), SECRET));
    }

    @Test
    void responseAuthenticatorAndMessageAuthenticatorAreValid() throws Exception {
        byte[] requestAuthenticator = HEX.parseHex("ffeeddccbbaa99887766554433221100");
        byte[] response = RadiusCrypto.buildResponse(ACCESS_ACCEPT, 9, requestAuthenticator,
                List.of(RadiusAttribute.ofString(ATTR_PROXY_STATE, "ps")), SECRET);
        RadiusPacket packet = RadiusPacket.decode(response, response.length);

        assertEquals(ACCESS_ACCEPT, packet.getCode());
        assertEquals(9, packet.getIdentifier());
        assertEquals(ATTR_MESSAGE_AUTHENTICATOR, packet.getAttributes().get(0).getType());
        assertTrue(RadiusCrypto.verifyResponse(packet, requestAuthenticator, SECRET));
        assertFalse(RadiusCrypto.verifyResponse(packet, new byte[16], SECRET));

        response[response.length - 1] ^= 1;
        assertFalse(RadiusCrypto.verifyResponse(RadiusPacket.decode(response, response.length), requestAuthenticator, SECRET));
    }

    @Test
    void decodeRejectsMalformedPackets() {
        assertThrows(RadiusException.class, () -> RadiusPacket.decode(new byte[19], 19));

        byte[] badLength = new byte[20];
        badLength[0] = ACCESS_REQUEST;
        badLength[3] = 30;
        assertThrows(RadiusException.class, () -> RadiusPacket.decode(badLength, 20));

        byte[] badAttribute = new byte[23];
        badAttribute[0] = ACCESS_REQUEST;
        badAttribute[3] = 23;
        badAttribute[20] = ATTR_USER_NAME;
        badAttribute[21] = 1;
        assertThrows(RadiusException.class, () -> RadiusPacket.decode(badAttribute, 23));

        byte[] overflowing = new byte[23];
        overflowing[0] = ACCESS_REQUEST;
        overflowing[3] = 23;
        overflowing[20] = ATTR_USER_NAME;
        overflowing[21] = 10;
        assertThrows(RadiusException.class, () -> RadiusPacket.decode(overflowing, 23));
    }

    @Test
    void decodeIgnoresPaddingBeyondLengthField() throws Exception {
        byte[] packet = RadiusPacket.encode(ACCESS_REQUEST, 1, new byte[16],
                List.of(RadiusAttribute.ofString(ATTR_USER_NAME, "bob")));
        byte[] padded = new byte[packet.length + 10];
        System.arraycopy(packet, 0, padded, 0, packet.length);
        RadiusPacket decoded = RadiusPacket.decode(padded, padded.length);
        assertEquals(packet.length, decoded.getRawBytes().length);
        assertEquals("bob", decoded.getAttribute(ATTR_USER_NAME).orElseThrow().getValueAsString());
    }
}
