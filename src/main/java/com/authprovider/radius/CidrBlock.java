package com.authprovider.radius;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * An IP address or CIDR subnet (IPv4 or IPv6) parsed without DNS lookups. A discrete address is
 * treated as a full-length prefix ({@code /32} or {@code /128}).
 */
public final class CidrBlock {

    private static final Pattern IPV4 = Pattern.compile("^\\d{1,3}(\\.\\d{1,3}){3}$");
    private static final Pattern IPV6 = Pattern.compile("^[0-9a-fA-F:.]*:[0-9a-fA-F:.]*$");

    private final byte[] network;
    private final int prefixLength;
    private final String text;

    private CidrBlock(byte[] network, int prefixLength, String text) {
        this.network = network;
        this.prefixLength = prefixLength;
        this.text = text;
    }

    /**
     * Parses {@code a.b.c.d}, {@code a.b.c.d/n}, an IPv6 literal or an IPv6 CIDR.
     *
     * @throws IllegalArgumentException if the value is not an IP literal / CIDR block
     */
    public static CidrBlock parse(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Address must not be empty");
        }
        String trimmed = value.trim();
        String addressPart = trimmed;
        Integer prefix = null;
        int slash = trimmed.indexOf('/');
        if (slash >= 0) {
            addressPart = trimmed.substring(0, slash).trim();
            String prefixPart = trimmed.substring(slash + 1).trim();
            if (prefixPart.isEmpty() || prefixPart.length() > 3 || !prefixPart.chars().allMatch(Character::isDigit)) {
                throw new IllegalArgumentException("Invalid CIDR prefix length: " + value);
            }
            prefix = Integer.parseInt(prefixPart);
        }
        byte[] bytes = literalBytes(addressPart);
        if (bytes == null) {
            throw new IllegalArgumentException("Not an IP address or CIDR block: " + value);
        }
        int maxPrefix = bytes.length * 8;
        int length = prefix == null ? maxPrefix : prefix;
        if (length < 0 || length > maxPrefix) {
            throw new IllegalArgumentException("CIDR prefix length out of range: " + value);
        }
        byte[] masked = mask(bytes, length);
        return new CidrBlock(masked, length, trimmed);
    }

    /** @return true if {@code value} is a syntactically valid IP literal or CIDR block. */
    public static boolean isValid(String value) {
        try {
            parse(value);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    public boolean matches(InetAddress address) {
        if (address == null) {
            return false;
        }
        byte[] candidate = address.getAddress();
        if (candidate.length != network.length) {
            candidate = convertFamily(candidate, network.length);
            if (candidate == null) {
                return false;
            }
        }
        return java.util.Arrays.equals(mask(candidate, prefixLength), network);
    }

    public int getPrefixLength() {
        return prefixLength;
    }

    public boolean isSingleAddress() {
        return prefixLength == network.length * 8;
    }

    @Override
    public String toString() {
        return text;
    }

    private static byte[] literalBytes(String address) {
        if (address.isEmpty()) {
            return null;
        }
        String candidate = address;
        if (candidate.startsWith("[") && candidate.endsWith("]")) {
            candidate = candidate.substring(1, candidate.length() - 1);
        }
        if (IPV4.matcher(candidate).matches()) {
            String[] parts = candidate.split("\\.");
            byte[] bytes = new byte[4];
            for (int i = 0; i < 4; i++) {
                int octet = Integer.parseInt(parts[i]);
                if (octet > 255) {
                    return null;
                }
                bytes[i] = (byte) octet;
            }
            return bytes;
        }
        if (IPV6.matcher(candidate).matches() && !candidate.toLowerCase(Locale.ROOT).contains("%")) {
            try {
                // An IPv6 literal never triggers a DNS lookup.
                return InetAddress.getByName(candidate).getAddress();
            } catch (UnknownHostException e) {
                return null;
            }
        }
        return null;
    }

    /** Maps IPv4-mapped IPv6 addresses (::ffff:a.b.c.d) to IPv4 and vice versa. */
    private static byte[] convertFamily(byte[] address, int targetLength) {
        if (address.length == 16 && targetLength == 4) {
            for (int i = 0; i < 10; i++) {
                if (address[i] != 0) {
                    return null;
                }
            }
            if (address[10] != (byte) 0xff || address[11] != (byte) 0xff) {
                return null;
            }
            return java.util.Arrays.copyOfRange(address, 12, 16);
        }
        if (address.length == 4 && targetLength == 16) {
            byte[] mapped = new byte[16];
            mapped[10] = (byte) 0xff;
            mapped[11] = (byte) 0xff;
            System.arraycopy(address, 0, mapped, 12, 4);
            return mapped;
        }
        return null;
    }

    private static byte[] mask(byte[] address, int prefixLength) {
        byte[] result = address.clone();
        for (int i = 0; i < result.length; i++) {
            int bitsInByte = Math.max(0, Math.min(8, prefixLength - i * 8));
            int byteMask = bitsInByte == 0 ? 0 : (0xFF << (8 - bitsInByte)) & 0xFF;
            result[i] = (byte) (result[i] & byteMask);
        }
        return result;
    }
}
