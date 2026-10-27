package com.authprovider.radius;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;

public class RadiusAttribute {

    private final int type;
    private final byte[] value;

    public RadiusAttribute(int type, byte[] value) {
        if (type < 1 || type > 255) {
            throw new IllegalArgumentException("Invalid attribute type: " + type);
        }
        Objects.requireNonNull(value, "value");
        if (value.length > RadiusConstants.MAX_ATTRIBUTE_VALUE_LENGTH) {
            throw new IllegalArgumentException("Attribute value too long: " + value.length);
        }
        this.type = type;
        this.value = value.clone();
    }

    public static RadiusAttribute ofString(int type, String value) {
        return new RadiusAttribute(type, value.getBytes(StandardCharsets.UTF_8));
    }

    public static RadiusAttribute ofInteger(int type, long value) {
        return new RadiusAttribute(type, ByteBuffer.allocate(4).putInt((int) value).array());
    }

    public int getType() {
        return type;
    }

    public int type() {
        return type;
    }

    public byte[] getValue() {
        return value.clone();
    }

    public byte[] value() {
        return value.clone();
    }

    public int getValueLength() {
        return value.length;
    }

    public String getValueAsString() {
        return new String(value, StandardCharsets.UTF_8);
    }

    public long getValueAsInteger() {
        if (value.length != 4) {
            throw new IllegalStateException("Attribute is not a 32-bit integer");
        }
        return ByteBuffer.wrap(value).getInt() & 0xFFFFFFFFL;
    }

    public RadiusAttribute orElseThrow() {
        return this;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof RadiusAttribute other)) {
            return false;
        }
        return type == other.type && Arrays.equals(value, other.value);
    }

    @Override
    public int hashCode() {
        return 31 * type + Arrays.hashCode(value);
    }

    @Override
    public String toString() {
        return "RadiusAttribute{type=" + type + ", length=" + value.length + "}";
    }
}
