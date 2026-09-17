package com.authprovider.service;

import lombok.RequiredArgsConstructor;
import org.apache.commons.codec.binary.Base32;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;

@Primary
@Component
@RequiredArgsConstructor(onConstructor_ = @Autowired)
public class Base32SecretGenerator implements SecretGenerator {

    private static final int DEFAULT_SECRET_SIZE = 20;

    private final SecureRandom secureRandom;
    private final Base32 base32;

    public Base32SecretGenerator() {
        this(new SecureRandom(), new Base32());
    }

    @Override
    public String generateSecret() {
        byte[] bytes = new byte[DEFAULT_SECRET_SIZE];
        secureRandom.nextBytes(bytes);
        return base32.encodeToString(bytes);
    }
}
