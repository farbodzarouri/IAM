package com.authprovider.oauth2;

public class InvalidJwsException extends RuntimeException {
    public InvalidJwsException(String message) {
        super(message);
    }
}
