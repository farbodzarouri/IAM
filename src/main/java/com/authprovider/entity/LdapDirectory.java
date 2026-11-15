package com.authprovider.entity;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

import java.time.Instant;

/**
 * A federated LDAP / Active Directory. Requests qualified with a realm ({@code REALM\\user} or
 * {@code user@realm}) are routed to the directory whose {@code realm} matches; unqualified requests
 * are evaluated against all enabled directories in ascending {@code priority} order.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "ldap_directories", uniqueConstraints = {
        @UniqueConstraint(name = "uk_ldap_directories_name", columnNames = {"name"})
})
public class LdapDirectory {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "name", nullable = false, length = 128)
    private String name;

    /**
     * Realm identifier(s) used to route qualified user names, e.g. {@code CORP} or {@code corp.example.com}.
     * Multiple aliases may be given separated by commas. {@code null} means the directory only serves
     * unqualified names (and qualified names whose realm matches no directory).
     */
    @Column(name = "realm", length = 512)
    private String realm;

    @Builder.Default
    @Column(name = "enabled", nullable = false)
    private boolean enabled = true;

    /** Lower values are evaluated first. */
    @Builder.Default
    @Column(name = "priority", nullable = false)
    private int priority = 100;

    @Column(name = "url", nullable = false, length = 1024)
    private String url;

    @Column(name = "base_dn", length = 512)
    private String baseDn;

    @Column(name = "user_search_filter", length = 1024)
    private String userSearchFilter;

    @Column(name = "user_dn_pattern", length = 512)
    private String userDnPattern;

    @Column(name = "bind_dn", length = 512)
    private String bindDn;

    @ToString.Exclude
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    @Column(name = "bind_password", length = 512)
    private String bindPassword;

    @Builder.Default
    @Column(name = "auto_provision", nullable = false)
    private boolean autoProvision = true;

    @Builder.Default
    @Column(name = "fallback_to_local", nullable = false)
    private boolean fallbackToLocal = false;

    @Builder.Default
    @Column(name = "connect_timeout_ms", nullable = false)
    private int connectTimeoutMs = 5000;

    @Builder.Default
    @Column(name = "read_timeout_ms", nullable = false)
    private int readTimeoutMs = 10000;

    @Builder.Default
    @Column(name = "referral", length = 32)
    private String referral = "ignore";

    /** Comma separated list of attributes holding the canonical user name. */
    @Builder.Default
    @Column(name = "username_attributes", length = 512)
    private String usernameAttributes = "uid,sAMAccountName";

    @Column(name = "created_at")
    private Instant createdAt;

    @Column(name = "updated_at")
    private Instant updatedAt;

    @PrePersist
    void onCreate() {
        Instant now = Instant.now();
        if (createdAt == null) {
            createdAt = now;
        }
        updatedAt = now;
    }

    @PreUpdate
    void onUpdate() {
        updatedAt = Instant.now();
    }
}
