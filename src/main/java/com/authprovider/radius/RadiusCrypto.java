package com.authprovider.radius;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static com.authprovider.radius.RadiusConstants.*;

public final class RadiusCrypto {

    private static final String HMAC_MD5 = "HmacMD5";

    private RadiusCrypto() {
    }

    public static byte[] md5(byte[]... parts) {
        MessageDigest digest = newMd5();
        for (byte[] part : parts) {
            digest.update(part);
        }
        return digest.digest();
    }

    public static byte[] hmacMd5(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance(HMAC_MD5);
            mac.init(new SecretKeySpec(key, HMAC_MD5));
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC-MD5 unavailable", e);
        }
    }

    public static byte[] encryptUserPassword(byte[] password, byte[] secret, byte[] requestAuthenticator) {
        if (password.length > MAX_USER_PASSWORD_LENGTH) {
            throw new IllegalArgumentException("Password too long");
        }
        int paddedLength = Math.max(MIN_USER_PASSWORD_LENGTH, ((password.length + 15) / 16) * 16);
        byte[] padded = Arrays.copyOf(password, paddedLength);
        byte[] result = new byte[paddedLength];
        byte[] previous = requestAuthenticator;
        for (int offset = 0; offset < paddedLength; offset += 16) {
            byte[] b = md5(secret, previous);
            for (int i = 0; i < 16; i++) {
                result[offset + i] = (byte) (padded[offset + i] ^ b[i]);
            }
            previous = Arrays.copyOfRange(result, offset, offset + 16);
        }
        Arrays.fill(padded, (byte) 0);
        return result;
    }

    public static byte[] decryptUserPassword(byte[] cipher, byte[] secret, byte[] requestAuthenticator) throws RadiusException {
        if (cipher.length < MIN_USER_PASSWORD_LENGTH || cipher.length > MAX_USER_PASSWORD_LENGTH || cipher.length % 16 != 0) {
            throw new RadiusException("Invalid User-Password length");
        }
        byte[] plain = new byte[cipher.length];
        byte[] previous = requestAuthenticator;
        for (int offset = 0; offset < cipher.length; offset += 16) {
            byte[] b = md5(secret, previous);
            for (int i = 0; i < 16; i++) {
                plain[offset + i] = (byte) (cipher[offset + i] ^ b[i]);
            }
            previous = Arrays.copyOfRange(cipher, offset, offset + 16);
        }
        int end = plain.length;
        while (end > 0 && plain[end - 1] == 0) {
            end--;
        }
        byte[] result = Arrays.copyOf(plain, end);
        Arrays.fill(plain, (byte) 0);
        return result;
    }

    public static boolean verifyRequestMessageAuthenticator(RadiusPacket packet, byte[] secret) {
        if (!packet.hasMessageAuthenticator()) {
            return false;
        }
        byte[] copy = packet.getRawBytes();
        int offset = packet.getMessageAuthenticatorOffset();
        byte[] received = Arrays.copyOfRange(copy, offset, offset + MESSAGE_AUTHENTICATOR_LENGTH);
        Arrays.fill(copy, offset, offset + MESSAGE_AUTHENTICATOR_LENGTH, (byte) 0);
        byte[] expected = hmacMd5(secret, copy);
        return MessageDigest.isEqual(expected, received);
    }

    public static byte[] buildResponse(int code, int identifier, byte[] requestAuthenticator,
                                       List<? extends RadiusAttribute> attributes, byte[] secret) {
        List<RadiusAttribute> withAuthenticator = new ArrayList<>(attributes.size() + 1);
        withAuthenticator.add(new RadiusAttribute(ATTR_MESSAGE_AUTHENTICATOR, new byte[MESSAGE_AUTHENTICATOR_LENGTH]));
        for (RadiusAttribute attribute : attributes) {
            if (attribute.getType() != ATTR_MESSAGE_AUTHENTICATOR) {
                withAuthenticator.add(attribute);
            }
        }
        byte[] packet = RadiusPacket.encode(code, identifier, requestAuthenticator, withAuthenticator);
        int maOffset = HEADER_LENGTH + 2;
        byte[] messageAuthenticator = hmacMd5(secret, packet);
        System.arraycopy(messageAuthenticator, 0, packet, maOffset, MESSAGE_AUTHENTICATOR_LENGTH);
        byte[] responseAuthenticator = md5(packet, secret);
        System.arraycopy(responseAuthenticator, 0, packet, 4, AUTHENTICATOR_LENGTH);
        return packet;
    }

    public static byte[] buildRequest(int code, int identifier, byte[] requestAuthenticator,
                                      List<? extends RadiusAttribute> attributes, byte[] secret, boolean addMessageAuthenticator) {
        List<RadiusAttribute> all = new ArrayList<>(attributes.size() + 1);
        if (addMessageAuthenticator) {
            all.add(new RadiusAttribute(ATTR_MESSAGE_AUTHENTICATOR, new byte[MESSAGE_AUTHENTICATOR_LENGTH]));
        }
        for (RadiusAttribute attribute : attributes) {
            if (attribute.getType() != ATTR_MESSAGE_AUTHENTICATOR) {
                all.add(attribute);
            }
        }
        byte[] packet = RadiusPacket.encode(code, identifier, requestAuthenticator, all);
        if (addMessageAuthenticator) {
            byte[] messageAuthenticator = hmacMd5(secret, packet);
            System.arraycopy(messageAuthenticator, 0, packet, HEADER_LENGTH + 2, MESSAGE_AUTHENTICATOR_LENGTH);
        }
        return packet;
    }

    public static boolean verifyResponse(RadiusPacket response, byte[] requestAuthenticator, byte[] secret) {
        byte[] raw = response.getRawBytes();
        byte[] received = Arrays.copyOfRange(raw, 4, HEADER_LENGTH);
        System.arraycopy(requestAuthenticator, 0, raw, 4, AUTHENTICATOR_LENGTH);
        byte[] expected = md5(raw, secret);
        if (!MessageDigest.isEqual(expected, received)) {
            return false;
        }
        if (response.hasMessageAuthenticator()) {
            int offset = response.getMessageAuthenticatorOffset();
            byte[] receivedMa = Arrays.copyOfRange(raw, offset, offset + MESSAGE_AUTHENTICATOR_LENGTH);
            Arrays.fill(raw, offset, offset + MESSAGE_AUTHENTICATOR_LENGTH, (byte) 0);
            return MessageDigest.isEqual(hmacMd5(secret, raw), receivedMa);
        }
        return true;
    }

    private static MessageDigest newMd5() {
        try {
            return MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("MD5 unavailable", e);
        }
    }
}
