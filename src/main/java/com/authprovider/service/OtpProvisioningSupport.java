package com.authprovider.service;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * Shared helper for building TOTP {@code otpauth://} provisioning URIs and QR code images.
 */
public final class OtpProvisioningSupport {

    public static final String DEFAULT_ISSUER = "IAM";
    public static final int DEFAULT_QR_SIZE = 200;

    public record ProvisioningQr(String otpAuthUri, String qrCode) {
    }

    private OtpProvisioningSupport() {
    }

    public static String encodeLabel(String value) {
        String safe = value == null ? "user" : value;
        return URLEncoder.encode(safe, StandardCharsets.UTF_8).replace("+", "%20");
    }

    public static String buildOtpAuthUri(QrCodeGenerator qrCodeGenerator, String label, String secret) {
        return qrCodeGenerator.generateOtpAuthUrl(DEFAULT_ISSUER, encodeLabel(label), secret);
    }

    public static String generateQrImage(QrCodeGenerator qrCodeGenerator, String otpAuthUri) throws Exception {
        return qrCodeGenerator.generateQrCodeImage(otpAuthUri, DEFAULT_QR_SIZE, DEFAULT_QR_SIZE);
    }

    public static ProvisioningQr generate(QrCodeGenerator qrCodeGenerator, String label, String secret)
            throws Exception {
        String otpAuthUri = buildOtpAuthUri(qrCodeGenerator, label, secret);
        String qrCode = generateQrImage(qrCodeGenerator, otpAuthUri);
        return new ProvisioningQr(otpAuthUri, qrCode);
    }
}
