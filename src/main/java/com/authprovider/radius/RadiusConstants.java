package com.authprovider.radius;

public final class RadiusConstants {

    public static final int ACCESS_REQUEST = 1;
    public static final int ACCESS_ACCEPT = 2;
    public static final int ACCESS_REJECT = 3;
    public static final int ACCOUNTING_REQUEST = 4;
    public static final int ACCESS_CHALLENGE = 11;
    public static final int STATUS_SERVER = 12;

    public static final int ATTR_USER_NAME = 1;
    public static final int ATTR_USER_PASSWORD = 2;
    public static final int ATTR_CHAP_PASSWORD = 3;
    public static final int ATTR_REPLY_MESSAGE = 18;
    public static final int ATTR_STATE = 24;
    public static final int ATTR_SESSION_TIMEOUT = 27;
    public static final int ATTR_PROXY_STATE = 33;
    public static final int ATTR_CHAP_CHALLENGE = 60;
    public static final int ATTR_EAP_MESSAGE = 79;
    public static final int ATTR_MESSAGE_AUTHENTICATOR = 80;

    public static final int HEADER_LENGTH = 20;
    public static final int AUTHENTICATOR_LENGTH = 16;
    public static final int MIN_PACKET_LENGTH = 20;
    public static final int MAX_PACKET_LENGTH = 4096;
    public static final int MAX_ATTRIBUTE_VALUE_LENGTH = 253;
    public static final int MESSAGE_AUTHENTICATOR_LENGTH = 16;
    public static final int MIN_USER_PASSWORD_LENGTH = 16;
    public static final int MAX_USER_PASSWORD_LENGTH = 128;

    private RadiusConstants() {
    }
}
