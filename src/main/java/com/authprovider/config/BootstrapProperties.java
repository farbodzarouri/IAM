package com.authprovider.config;

import lombok.Data;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * Optional first-boot seeding overrides used solely when the corresponding database tables are empty
 * ({@code admins}, {@code radius_clients}, {@code security_policies}). Never store production secrets
 * in source-controlled configuration files; pass them via environment variables or use the first-run
 * {@code /setup} wizard.
 */
@Data
@ConfigurationProperties(prefix = "iam.bootstrap")
public class BootstrapProperties {

    private boolean seedDefaults = true;
    private Admin admin = new Admin();
    private Radius radius = new Radius();
    private Policy policy = new Policy();

    @Data
    public static class Admin {
        private boolean enabled = true;
        private String username;
        @ToString.Exclude
        private String password;
        private String displayName;
    }

    @Data
    public static class Radius {
        @ToString.Exclude
        private String sharedSecret;
        private List<String> allowedClients = new ArrayList<>();
    }

    @Data
    public static class Policy {
        private Integer maxFailures;
        private Long lockoutSeconds;
        private Long challengeTtlSeconds;
        private Long mfaApprovalTtlSeconds;
    }
}
