package com.authprovider.radius;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Minimal RADIUS packet model and codec (RFC 2865 / RFC 3579) built on the JDK only.
 */
public final class RadiusPacket {

    public static final int ACCESS_REQUEST = 1;
    public static final int ACCESS_ACCEPT = 2;
    public static final int ACCESS_REJECT = 3;

    public static final int ATTR_USER_NAME = 1;
    public static final int ATTR_USER_PASSWORD = 2;
    public static final int ATTR_CHAP_PASSWORD = 3;
    public static final int ATTR_REPLY_MESSAGE = 18;
    public static final int ATTR_PROXY_STATE = 33;
    public static final int ATTR_EAP_MESSAGE = 79;
    public static final int ATTR_MESSAGE_AUTHENTICATOR = 80;

    public static final int HEADER_LENGTH = 20;
    public static final int AUTHENTICATOR_LENGTH = 16;
    public static final int MIN_LENGTH = 20;
    public static final int MAX_LENGTH = 4096;
    private static final int MESSAGE_AUTHENTICATOR_ATTR_LENGTH = 18;

    /** A single RADIUS attribute (type + raw value). */
    public record Attribute(int type, byte[] value) {
        public Attribute {
            if (type < 1 || type > 255) {
                throw new IllegalArgumentException("Invalid attribute type " + type);
            }
            if (value == null || value.length > 253) {
                throw new IllegalArgumentException("Invalid attribute value length");
            }
        }
    }

    private final int code;
    private final int identifier;
    private final byte[] authenticator;
    private final List<Attribute> attributes;
    /** Raw bytes as received (trimmed to the Length field); null for locally built packets. */
    private final byte[] raw;

    private RadiusPacket(int code, int identifier, byte[] authenticator, List<Attribute> attributes, byte[] raw) {
        this.code = code;
        this.identifier = identifier;
        this.authenticator = authenticator;
        this.attributes = Collections.unmodifiableList(attributes);
        this.raw = raw;
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

    public List<Attribute> getAttributes() {
        return attributes;
    }

    public List<Attribute> getAttributes(int type) {
        List<Attribute> result = new ArrayList<>();
        for (Attribute a : attributes) {
            if (a.type() == type) {
                result.add(a);
            }
        }
        return result;
    }

    public Attribute getAttribute(int type) {
        for (Attribute a : attributes) {
            if (a.type() == type) {
                return a;
            }
        }
        return null;
    }

    public String getUserName() {
        Attribute a = getAttribute(ATTR_USER_NAME);
        return a == null ? null : new String(a.value(), StandardCharsets.UTF_8);
    }

    /**
     * Parses a datagram. Throws {@link IllegalArgumentException} for malformed packets which,
     * per RFC 2865 section 3, must be silently discarded.
     */
    public static RadiusPacket decode(byte[] data, int offset, int received) {
        if (received < MIN_LENGTH) {
            throw new IllegalArgumentException("Packet shorter than minimum length");
        }
        int length = ((data[offset + 2] & 0xff) << 8) | (data[offset + 3] & 0xff);
        if (length < MIN_LENGTH || length > MAX_LENGTH) {
            throw new IllegalArgumentException("Invalid length field " + length);
        }
        if (length > received) {
            throw new IllegalArgumentException("Packet truncated");
        }
        // Octets beyond the Length field are padding and MUST be ignored.
        byte[] raw = new byte[length];
        System.arraycopy(data, offset, raw, 0, length);

        int code = raw[0] & 0xff;
        int identifier = raw[1] & 0xff;
        byte[] authenticator = new byte[AUTHENTICATOR_LENGTH];
        System.arraycopy(raw, 4, authenticator, 0, AUTHENTICATOR_LENGTH);

        List<Attribute> attributes = new ArrayList<>();
        int pos = HEADER_LENGTH;
        while (pos < length) {
            if (pos + 2 > length) {
                throw new IllegalArgumentException("Truncated attribute header");
            }
            int type = raw[pos] & 0xff;
            int attrLen = raw[pos + 1] & 0xff;
            if (type == 0 || attrLen < 2 || pos + attrLen > length) {
                throw new IllegalArgumentException("Malformed attribute");
            }
            byte[] value = new byte[attrLen - 2];
            System.arraycopy(raw, pos + 2, value, 0, value.length);
            attributes.add(new Attribute(type, value));
            pos += attrLen;
        }
        return new RadiusPacket(code, identifier, authenticator, attributes, raw);
    }

    /**
     * Verifies the Message-Authenticator (RFC 3579 section 3.2) of a received Access-Request.
     *
     * @return true only if exactly one well-formed Message-Authenticator is present and valid
     */
    public boolean verifyRequestMessageAuthenticator(byte[] secret) {
        if (raw == null) {
            throw new IllegalStateException("Only received packets can be verified");
        }
        int found = -1;
        int pos = HEADER_LENGTH;
        while (pos < raw.length) {
            int type = raw[pos] & 0xff;
            int attrLen = raw[pos + 1] & 0xff;
            if (type == ATTR_MESSAGE_AUTHENTICATOR) {
                if (found >= 0 || attrLen != MESSAGE_AUTHENTICATOR_ATTR_LENGTH) {
                    return false;
                }
                found = pos;
            }
            pos += attrLen;
        }
        if (found < 0) {
            return false;
        }
        byte[] copy = raw.clone();
        byte[] received = new byte[16];
        System.arraycopy(copy, found + 2, received, 0, 16);
        java.util.Arrays.fill(copy, found + 2, found + 18, (byte) 0);
        byte[] expected = hmacMd5(secret, copy);
        return MessageDigest.isEqual(expected, received);
    }

    public boolean hasMessageAuthenticator() {
        return getAttribute(ATTR_MESSAGE_AUTHENTICATOR) != null;
    }

    /**
     * Builds an encoded response (Access-Accept / Access-Reject) to the given request.
     * A Message-Authenticator is placed first, followed by the supplied attributes and
     * all Proxy-State attributes copied unmodified and in order from the request (RFC 2865 5.33).
     */
    public static byte[] encodeResponse(int code, RadiusPacket request, List<Attribute> attributes, byte[] secret) {
        ByteArrayOutputStream attrs = new ByteArrayOutputStream();
        attrs.write(ATTR_MESSAGE_AUTHENTICATOR);
        attrs.write(MESSAGE_AUTHENTICATOR_ATTR_LENGTH);
        int messageAuthOffset = HEADER_LENGTH + 2;
        attrs.writeBytes(new byte[16]);
        for (Attribute a : attributes) {
            writeAttribute(attrs, a);
        }
        for (Attribute a : request.getAttributes(ATTR_PROXY_STATE)) {
            writeAttribute(attrs, a);
        }
        byte[] attrBytes = attrs.toByteArray();
        int length = HEADER_LENGTH + attrBytes.length;
        if (length > MAX_LENGTH) {
            throw new IllegalArgumentException("Response too large");
        }
        byte[] packet = new byte[length];
        packet[0] = (byte) code;
        packet[1] = (byte) request.getIdentifier();
        packet[2] = (byte) (length >> 8);
        packet[3] = (byte) length;
        // Message-Authenticator for responses uses the Request Authenticator (RFC 3579 3.2).
        System.arraycopy(request.authenticator, 0, packet, 4, AUTHENTICATOR_LENGTH);
        System.arraycopy(attrBytes, 0, packet, HEADER_LENGTH, attrBytes.length);
        byte[] mac = hmacMd5(secret, packet);
        System.arraycopy(mac, 0, packet, messageAuthOffset, 16);
        // Response Authenticator = MD5(Code+ID+Length+RequestAuth+Attributes+Secret) (RFC 2865 3).
        MessageDigest md5 = md5();
        md5.update(packet);
        md5.update(secret);
        System.arraycopy(md5.digest(), 0, packet, 4, AUTHENTICATOR_LENGTH);
        return packet;
    }

    /** Builds an encoded Access-Request (used by clients and tests). */
    public static byte[] encodeAccessRequest(int identifier, byte[] requestAuthenticator,
                                             List<Attribute> attributes, byte[] secret,
                                             boolean includeMessageAuthenticator) {
        ByteArrayOutputStream attrs = new ByteArrayOutputStream();
        int messageAuthOffset = -1;
        if (includeMessageAuthenticator) {
            attrs.write(ATTR_MESSAGE_AUTHENTICATOR);
            attrs.write(MESSAGE_AUTHENTICATOR_ATTR_LENGTH);
            attrs.writeBytes(new byte[16]);
            messageAuthOffset = HEADER_LENGTH + 2;
        }
        for (Attribute a : attributes) {
            writeAttribute(attrs, a);
        }
        byte[] attrBytes = attrs.toByteArray();
        int length = HEADER_LENGTH + attrBytes.length;
        byte[] packet = new byte[length];
        packet[0] = (byte) ACCESS_REQUEST;
        packet[1] = (byte) identifier;
        packet[2] = (byte) (length >> 8);
        packet[3] = (byte) length;
        System.arraycopy(requestAuthenticator, 0, packet, 4, AUTHENTICATOR_LENGTH);
        System.arraycopy(attrBytes, 0, packet, HEADER_LENGTH, attrBytes.length);
        if (messageAuthOffset > 0) {
            System.arraycopy(hmacMd5(secret, packet), 0, packet, messageAuthOffset, 16);
        }
        return packet;
    }

    /**
     * Verifies a received response against the original request authenticator
     * (Response Authenticator and, if present, Message-Authenticator).
     */
    public static boolean verifyResponse(byte[] response, int responseLength, byte[] requestAuthenticator, byte[] secret) {
        RadiusPacket p;
        try {
            p = decode(response, 0, responseLength);
        } catch (IllegalArgumentException e) {
            return false;
        }
        byte[] raw = p.raw.clone();
        byte[] receivedAuth = p.authenticator;
        System.arraycopy(requestAuthenticator, 0, raw, 4, AUTHENTICATOR_LENGTH);
        MessageDigest md5 = md5();
        md5.update(raw);
        md5.update(secret);
        if (!MessageDigest.isEqual(md5.digest(), receivedAuth)) {
            return false;
        }
        int pos = HEADER_LENGTH;
        while (pos < raw.length) {
            int type = raw[pos] & 0xff;
            int attrLen = raw[pos + 1] & 0xff;
            if (type == ATTR_MESSAGE_AUTHENTICATOR) {
                if (attrLen != MESSAGE_AUTHENTICATOR_ATTR_LENGTH) {
                    return false;
                }
                byte[] received = new byte[16];
                System.arraycopy(raw, pos + 2, received, 0, 16);
                java.util.Arrays.fill(raw, pos + 2, pos + 18, (byte) 0);
                return MessageDigest.isEqual(hmacMd5(secret, raw), received);
            }
            pos += attrLen;
        }
        return true;
    }

    private static void writeAttribute(ByteArrayOutputStream out, Attribute a) {
        out.write(a.type());
        out.write(a.value().length + 2);
        out.writeBytes(a.value());
    }

    static byte[] hmacMd5(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacMD5");
            mac.init(new SecretKeySpec(key, "HmacMD5"));
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacMD5 unavailable", e);
        }
    }

    static MessageDigest md5() {
        try {
            return MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("MD5 unavailable", e);
        }
    }
}
