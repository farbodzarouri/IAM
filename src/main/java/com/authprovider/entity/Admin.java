package com.authprovider.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

import java.time.Instant;

/**
 * Administrative principal distinct from {@link User} accounts. Links to a {@link Person} and
 * optionally to a shared or dedicated {@link OtpToken} owned by that {@link Person}, while keeping
 * separate primary credentials and directory routing from regular users.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "admins", uniqueConstraints = {
        @UniqueConstraint(name = "uk_admins_username", columnNames = {"username"})
})
public class Admin {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "username", nullable = false, unique = true, length = 256)
    private String username;

    @ToString.Exclude
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    @Column(name = "password", length = 256)
    private String password;

    @ToString.Exclude
    @JsonIgnore
    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "person_id", nullable = false)
    private Person person;

    @ToString.Exclude
    @JsonIgnore
    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "otp_token_id")
    private OtpToken otpToken;

    @Builder.Default
    @Column(name = "enabled", nullable = false)
    private boolean enabled = true;

    @Column(name = "created_at")
    private Instant createdAt;

    @Column(name = "updated_at")
    private Instant updatedAt;

    @JsonIgnore
    public String getEffectiveSecret() {
        return otpToken != null && otpToken.isEnabled() ? otpToken.getSecret() : null;
    }

    @JsonIgnore
    public boolean isAccountEnabled() {
        return enabled && (person == null || person.isEnabled());
    }
}
