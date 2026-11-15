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
 * A RADIUS client (NAS / NPS proxy / VPN gateway) permitted to send requests to this server.
 * {@code address} is either a discrete IP address (e.g. {@code 10.0.0.5}) or a CIDR subnet
 * (e.g. {@code 10.0.0.0/24}). Each client has its own shared secret.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "radius_clients", uniqueConstraints = {
        @UniqueConstraint(name = "uk_radius_clients_name", columnNames = {"name"})
})
public class RadiusClient {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "name", nullable = false, length = 128)
    private String name;

    /** IPv4/IPv6 address or CIDR block (e.g. {@code 192.168.1.0/24}). */
    @Column(name = "address", nullable = false, length = 64)
    private String address;

    @ToString.Exclude
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    @Column(name = "shared_secret", nullable = false, length = 256)
    private String sharedSecret;

    @Builder.Default
    @Column(name = "active", nullable = false)
    private boolean active = true;

    @Column(name = "description", length = 512)
    private String description;

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
