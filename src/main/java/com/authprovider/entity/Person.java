package com.authprovider.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * Natural identity representing a human user or administrator. A {@code Person} owns one or more
 * {@link OtpToken} second-factor generators and may hold separate {@link User} and {@link Admin}
 * accounts linked to those tokens.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "persons", uniqueConstraints = {
        @UniqueConstraint(name = "uk_persons_email", columnNames = "email"),
        @UniqueConstraint(name = "uk_persons_mobile", columnNames = "mobile"),
        @UniqueConstraint(name = "uk_persons_national_code", columnNames = "national_code")
})
public class Person {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "first_name", length = 128)
    private String firstName;

    @Column(name = "last_name", length = 128)
    private String lastName;

    @Column(name = "display_name", nullable = false, length = 256)
    private String displayName;

    @Column(name = "email", length = 256)
    private String email;

    @Column(name = "mobile", length = 32)
    private String mobile;

    @Column(name = "national_code", length = 32)
    private String nationalCode;

    @Builder.Default
    @Column(name = "enabled", nullable = false)
    private boolean enabled = true;

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
