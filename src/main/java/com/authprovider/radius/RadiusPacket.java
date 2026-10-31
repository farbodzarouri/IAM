package com.authprovider.radius;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static com.authprovider.radius.RadiusConstants.*;

public final class RadiusPacket {

    public static final int ACCESS_REQUEST = RadiusConstants.ACCESS_REQUEST;
    public static final int ACCESS_ACCEPT = RadiusConstants.ACCESS_ACCEPT;
    public static final int ACCESS_REJECT = RadiusConstants.ACCESS_REJECT;
    public static final int ACCESS_CHALLENGE = RadiusConstants.ACCESS_CHALLENGE;

    public static final int ATTR_USER_NAME = RadiusConstants.ATTR_USER_NAME;
    public static final int ATTR_USER_PASSWORD = RadiusConstants.ATTR_USER_PASSWORD;
    public static final int ATTR_CHAP_PASSWORD = RadiusConstants.ATTR_CHAP_PASSWORD;
    public static final int ATTR_REPLY_MESSAGE = RadiusConstants.ATTR_REPLY_MESSAGE;
    public static final int ATTR_STATE = RadiusConstants.ATTR_STATE;
    public static final int ATTR_SESSION_TIMEOUT = RadiusConstants.ATTR_SESSION_TIMEOUT;
    public static final int ATTR_PROXY_STATE = RadiusConstants.ATTR_PROXY_STATE;
    public static final int ATTR_EAP_MESSAGE = RadiusConstants.ATTR_EAP_MESSAGE;
    public static final int ATTR_MESSAGE_AUTHENTICATOR = RadiusConstants.ATTR_MESSAGE_AUTHENTICATOR;

    public static final int HEADER_LENGTH = RadiusConstants.HEADER_LENGTH;
    public static final int AUTHENTICATOR_LENGTH = RadiusConstants.AUTHENTICATOR_LENGTH;
    public static final int MIN_LENGTH = RadiusConstants.MIN_PACKET_LENGTH;
    public static final int MAX_LENGTH = RadiusConstants.MAX_PACKET_LENGTH;

    public static final class Attribute extends RadiusAttribute {
        public Attribute(int type, byte[] value) {
            super(type, value);
        }
    }

    private final int code;
    private final int identifier;
    private final byte[] authenticator;
    private final List<RadiusAttribute> attributes;
    private final byte[] rawBytes;
    private final int messageAuthenticatorOffset;

    private RadiusPacket(int code, int identifier, byte[] authenticator, List<RadiusAttribute> attributes,
                         byte[] rawBytes, int messageAuthenticatorOffset) {
        this.code = code;
        this.identifier = identifier;
        this.authenticator = authenticator;
        this.attributes = Collections.unmodifiableList(attributes);
        this.rawBytes = rawBytes;
        this.messageAuthenticatorOffset = messageAuthenticatorOffset;
    }

    public static RadiusPacket decode(byte[] data, int datagramLength) throws RadiusException {
        if (data == null || datagramLength < MIN_PACKET_LENGTH || datagramLength > data.length) {
            throw new RadiusException("Datagram shorter than RADIUS header");
        }
        int code = data[0] & 0xFF;
        int identifier = data[1] & 0xFF;
        int length = ((data[2] & 0xFF) << 8) | (data[3] & 0xFF);
        if (length < MIN_PACKET_LENGTH || length > MAX_PACKET_LENGTH) {
            throw new RadiusException("Invalid RADIUS length field: " + length);
        }
        if (length > datagramLength) {
            throw new RadiusException("Datagram shorter than RADIUS length field");
        }
        byte[] raw = Arrays.copyOf(data, length);
        byte[] authenticator = Arrays.copyOfRange(raw, 4, HEADER_LENGTH);

        List<RadiusAttribute> attributes = new ArrayList<>();
        int messageAuthenticatorOffset = -1;
        int pos = HEADER_LENGTH;
        while (pos < length) {
            if (pos + 2 > length) {
                throw new RadiusException("Truncated attribute header");
            }
            int type = raw[pos] & 0xFF;
            int attrLength = raw[pos + 1] & 0xFF;
            if (attrLength < 2 || pos + attrLength > length) {
                throw new RadiusException("Invalid attribute length");
            }
            if (type == 0) {
                throw new RadiusException("Invalid attribute type 0");
            }
            if (type == ATTR_MESSAGE_AUTHENTICATOR) {
                if (attrLength != 2 + MESSAGE_AUTHENTICATOR_LENGTH) {
                    throw new RadiusException("Invalid Message-Authenticator length");
                }
                if (messageAuthenticatorOffset >= 0) {
                    throw new RadiusException("Multiple Message-Authenticator attributes");
                }
                messageAuthenticatorOffset = pos + 2;
            }
            attributes.add(new Attribute(type, Arrays.copyOfRange(raw, pos + 2, pos + attrLength)));
            pos += attrLength;
        }
        return new RadiusPacket(code, identifier, authenticator, attributes, raw, messageAuthenticatorOffset);
    }

    public static RadiusPacket decode(byte[] data, int offset, int received) {
        if (data == null || offset < 0 || received < MIN_PACKET_LENGTH || offset + received > data.length) {
            throw new IllegalArgumentException("Packet shorter than minimum length");
        }
        byte[] slice = offset == 0 ? data : Arrays.copyOfRange(data, offset, offset + received);
        try {
            return decode(slice, received);
        } catch (RadiusException e) {
            throw new IllegalArgumentException(e.getMessage(), e);
        }
    }

    public static byte[] encode(int code, int identifier, byte[] authenticator, List<? extends RadiusAttribute> attributes) {
        if (authenticator == null || authenticator.length != AUTHENTICATOR_LENGTH) {
            throw new IllegalArgumentException("Authenticator must be 16 octets");
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(code);
        out.write(identifier);
        out.write(0);
        out.write(0);
        out.writeBytes(authenticator);
        for (RadiusAttribute attribute : attributes) {
            out.write(attribute.getType());
            out.write(attribute.getValueLength() + 2);
            out.writeBytes(attribute.getValue());
        }
        byte[] bytes = out.toByteArray();
        if (bytes.length > MAX_PACKET_LENGTH) {
            throw new IllegalArgumentException("RADIUS packet exceeds maximum length");
        }
        bytes[2] = (byte) (bytes.length >> 8);
        bytes[3] = (byte) bytes.length;
        return bytes;
    }

    public static byte[] encodeAccessRequest(int identifier, byte[] requestAuthenticator,
                                             List<? extends RadiusAttribute> attributes, byte[] secret,
                                             boolean includeMessageAuthenticator) {
        return RadiusCrypto.buildRequest(ACCESS_REQUEST, identifier, requestAuthenticator, attributes, secret, includeMessageAuthenticator);
    }

    public static byte[] encodeResponse(int code, RadiusPacket request, List<? extends RadiusAttribute> attributes, byte[] secret) {
        List<RadiusAttribute> all = new ArrayList<>(attributes);
        all.addAll(request.getAttributes(ATTR_PROXY_STATE));
        return RadiusCrypto.buildResponse(code, request.getIdentifier(), request.getAuthenticator(), all, secret);
    }

    public static boolean verifyResponse(byte[] response, int responseLength, byte[] requestAuthenticator, byte[] secret) {
        try {
            RadiusPacket decoded = decode(response, responseLength);
            return RadiusCrypto.verifyResponse(decoded, requestAuthenticator, secret);
        } catch (RadiusException e) {
            return false;
        }
    }

    public boolean verifyRequestMessageAuthenticator(byte[] secret) {
        return RadiusCrypto.verifyRequestMessageAuthenticator(this, secret);
    }

    public int getCode() {
        return code;
    }

    public int getIdentifier() {
        return identifier;
    }

    public byte[] getAuthenticator() {
        return authenticator.clone();
    }

    public List<RadiusAttribute> getAttributes() {
        return attributes;
    }

    public List<RadiusAttribute> getAttributes(int type) {
        List<RadiusAttribute> result = new ArrayList<>();
        for (RadiusAttribute attribute : attributes) {
            if (attribute.getType() == type) {
                result.add(attribute);
            }
        }
        return result;
    }

    public RadiusAttribute getAttribute(int type) {
        for (RadiusAttribute attribute : attributes) {
            if (attribute.getType() == type) {
                return attribute;
            }
        }
        return null;
    }

    public Optional<RadiusAttribute> findAttribute(int type) {
        return Optional.ofNullable(getAttribute(type));
    }

    public String getUserName() {
        RadiusAttribute a = getAttribute(ATTR_USER_NAME);
        return a == null ? null : new String(a.getValue(), StandardCharsets.UTF_8);
    }

    public int countAttributes(int type) {
        int count = 0;
        for (RadiusAttribute attribute : attributes) {
            if (attribute.getType() == type) {
                count++;
            }
        }
        return count;
    }

    public byte[] getRawBytes() {
        return rawBytes.clone();
    }

    public boolean hasMessageAuthenticator() {
        return messageAuthenticatorOffset >= 0;
    }

    int getMessageAuthenticatorOffset() {
        return messageAuthenticatorOffset;
    }

    byte[] rawBytesUnsafe() {
        return rawBytes;
    }
}
