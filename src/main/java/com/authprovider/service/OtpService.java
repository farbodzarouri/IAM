package com.authprovider.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

@Service
public class OtpService implements SecretGenerator, TotpService, OcraService {

    private final SecretGenerator secretGenerator;
    private final TotpService totpService;
    private final OcraService ocraService;

    @Autowired
    public OtpService(
            @Qualifier("base32SecretGenerator") SecretGenerator secretGenerator,
            @Qualifier("totpServiceImpl") TotpService totpService,
            @Qualifier("ocraServiceImpl") OcraService ocraService) {
        this.secretGenerator = secretGenerator;
        this.totpService = totpService;
        this.ocraService = ocraService;
    }

    public OtpService() {
        this(new Base32SecretGenerator(), new TotpServiceImpl(), new OcraServiceImpl());
    }

    @Override
    public String generateSecret() {
        return secretGenerator.generateSecret();
    }

    @Override
    public boolean validateOtp(String secret, int otp) {
        return totpService.validateOtp(secret, otp);
    }

    @Override
    public int generateOtp(String secret) {
        return totpService.generateOtp(secret);
    }

    @Override
    public String generateOcra(String secret, String challenge) {
        return ocraService.generateOcra(secret, challenge);
    }

    @Override
    public boolean validateOcra(String secret, String challenge, String otp) {
        return ocraService.validateOcra(secret, challenge, otp);
    }
}
