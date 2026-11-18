package com.authprovider.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * Records an OCRA challenge that has been answered successfully for a user. The unique constraint makes
 * each (user, challenge) pair single-use across all channels and cluster nodes.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "ocra_challenge_uses", uniqueConstraints = {
        @UniqueConstraint(name = "uk_ocra_challenge_uses_subject_challenge", columnNames = {"subject_key", "challenge_hash"})
})
public class OcraChallengeUse {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "subject_key", nullable = false, length = 64)
    private String subjectKey;

    @Column(name = "user_id")
    private Long userId;

    /** Hex encoded SHA-256 of the challenge. */
    @Column(name = "challenge_hash", nullable = false, length = 64)
    private String challengeHash;

    @Column(name = "used_at", nullable = false)
    private Instant usedAt;
}
