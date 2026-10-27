package com.authprovider.radius;

public class RadiusException extends Exception {

    public RadiusException(String message) {
        super(message);
    }

    public RadiusException(String message, Throwable cause) {
        super(message, cause);
    }
}
