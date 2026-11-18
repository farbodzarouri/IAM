package com.authprovider.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "users", uniqueConstraints = {
        @UniqueConstraint(name = "uk_users_username", columnNames = {"username"})
})
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "username", nullable = false, unique = true)
    private String username;

    @ToString.Exclude
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private String password;

    @ToString.Exclude
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private String secret;

    @ToString.Exclude
    @JsonIgnore
    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "person_id")
    private Person person;

    @ToString.Exclude
    @JsonIgnore
    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "otp_token_id")
    private OtpToken otpToken;

    @Builder.Default
    @Column(name = "enabled", nullable = false)
    private boolean enabled = true;

    /** Optional per-account authentication mode override (null inherits client/policy default). */
    @Enumerated(EnumType.STRING)
    @Column(name = "auth_mode", length = 32)
    private AuthMode authMode;

    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    public String getSecret() {
        if (otpToken != null) {
            return otpToken.isEnabled() ? otpToken.getSecret() : null;
        }
        return secret;
    }

    @JsonIgnore
    public String getRawSecret() {
        return secret;
    }

    @JsonIgnore
    public boolean isAccountEnabled() {
        return enabled && (person == null || person.isEnabled());
    }
}
