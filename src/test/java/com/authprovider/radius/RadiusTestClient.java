package com.authprovider.radius;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static com.authprovider.radius.RadiusConstants.*;

class RadiusTestClient implements AutoCloseable {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final DatagramSocket socket;
    private final int serverPort;
    private final byte[] secret;
    private int nextIdentifier = 0;

    RadiusTestClient(int serverPort, String secret) throws IOException {
        this.socket = new DatagramSocket();
        this.socket.setSoTimeout(1500);
        this.serverPort = serverPort;
        this.secret = secret.getBytes(StandardCharsets.UTF_8);
    }

    record Request(int identifier, byte[] authenticator, byte[] bytes) {
    }

    Request accessRequest(String userName, String password, byte[] state, List<RadiusAttribute> extra, boolean messageAuthenticator) {
        byte[] authenticator = new byte[16];
        RANDOM.nextBytes(authenticator);
        List<RadiusAttribute> attributes = new ArrayList<>();
        if (userName != null) {
            attributes.add(RadiusAttribute.ofString(ATTR_USER_NAME, userName));
        }
        if (password != null) {
            attributes.add(new RadiusAttribute(ATTR_USER_PASSWORD,
                    RadiusCrypto.encryptUserPassword(password.getBytes(StandardCharsets.UTF_8), secret, authenticator)));
        }
        if (state != null) {
            attributes.add(new RadiusAttribute(ATTR_STATE, state));
        }
        attributes.addAll(extra);
        int identifier = nextIdentifier++ & 0xFF;
        return new Request(identifier, authenticator,
                RadiusCrypto.buildRequest(ACCESS_REQUEST, identifier, authenticator, attributes, secret, messageAuthenticator));
    }

    Request accessRequest(String userName, String password, byte[] state) {
        return accessRequest(userName, password, state, List.of(), true);
    }

    Request raw(int code, List<RadiusAttribute> attributes, boolean messageAuthenticator) {
        byte[] authenticator = new byte[16];
        RANDOM.nextBytes(authenticator);
        int identifier = nextIdentifier++ & 0xFF;
        return new Request(identifier, authenticator,
                RadiusCrypto.buildRequest(code, identifier, authenticator, attributes, secret, messageAuthenticator));
    }

    Optional<RadiusPacket> send(Request request) throws Exception {
        socket.send(new DatagramPacket(request.bytes(), request.bytes().length, InetAddress.getLoopbackAddress(), serverPort));
        byte[] buffer = new byte[MAX_PACKET_LENGTH];
        DatagramPacket datagram = new DatagramPacket(buffer, buffer.length);
        try {
            socket.receive(datagram);
        } catch (SocketTimeoutException e) {
            return Optional.empty();
        }
        RadiusPacket response = RadiusPacket.decode(datagram.getData(), datagram.getLength());
        if (response.getIdentifier() != request.identifier()) {
            throw new AssertionError("Response identifier mismatch");
        }
        if (!RadiusCrypto.verifyResponse(response, request.authenticator(), secret)) {
            throw new AssertionError("Response authenticator invalid");
        }
        if (!response.hasMessageAuthenticator()) {
            throw new AssertionError("Response lacks Message-Authenticator");
        }
        return Optional.of(response);
    }

    RadiusPacket sendExpectingResponse(Request request) throws Exception {
        return send(request).orElseThrow(() -> new AssertionError("No RADIUS response received"));
    }

    @Override
    public void close() {
        socket.close();
    }
}
