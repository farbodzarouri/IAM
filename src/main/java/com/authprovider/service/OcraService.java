package com.authprovider.service;

public interface OcraService {
    String generateOcra(String secret, String challenge);
    boolean validateOcra(String secret, String challenge, String otp);
}
