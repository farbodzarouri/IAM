package com.authprovider.exception;

public class SetupAlreadyCompletedException extends RuntimeException {
    public SetupAlreadyCompletedException(String message) {
        super(message);
    }
}
