package com.authprovider.service;

import com.google.zxing.WriterException;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class QrCodeServiceTest {

    private final QrCodeService qrCodeService = new QrCodeService();

    @Test
    public void testGenerateQrCodeImage() throws WriterException, IOException {
        String text = "otpauth://totp/Test:user?secret=JBSWY3DPEHPK3PXP&issuer=Test";
        int width = 200;
        int height = 200;

        String base64Image = qrCodeService.generateQrCodeImage(text, width, height);

        assertNotNull(base64Image);
        assertTrue(base64Image.length() > 0);
        // Base64 string usually ends with = or ==
        assertTrue(base64Image.matches("^[A-Za-z0-9+/]+={0,2}$"));
    }
}
