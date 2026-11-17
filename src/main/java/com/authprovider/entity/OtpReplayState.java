package com.authprovider.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * Highest TOTP time step accepted for a user, shared by every authentication channel and every cluster
 * node. A code is only accepted when its time step is strictly greater than the stored one, which is
 * enforced atomically by a conditional {@code UPDATE} (see {@code OtpReplayStateRepository#advance}).
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "otp_replay_state", uniqueConstraints = {
        @UniqueConstraint(name = "uk_otp_replay_state_user", columnNames = {"user_id"})
})
public class OtpReplayState {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(name = "last_time_step", nullable = false)
    private long lastTimeStep;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;
}
