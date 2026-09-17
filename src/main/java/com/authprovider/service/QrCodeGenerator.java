package com.authprovider.service;

import com.google.zxing.WriterException;

import java.io.IOException;

public interface QrCodeGenerator {
    String generateQrCodeImage(String text, int width, int height) throws WriterException, IOException;
    String generateOtpAuthUrl(String issuer, String username, String secret);
}
