package com.authprovider.repository;

import com.authprovider.entity.RadiusChallengeSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;

@Repository
public interface RadiusChallengeSessionRepository extends JpaRepository<RadiusChallengeSession, Long> {
    Optional<RadiusChallengeSession> findByState(String state);

    boolean existsByState(String state);

    long countByExpiresAtAfter(Instant now);

    /** Atomically consumes the session; returns 1 only for the single caller that removed it. */
    @Transactional
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("delete from RadiusChallengeSession s where s.id = :id")
    int deleteByIdReturningCount(@Param("id") Long id);

    @Transactional
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("delete from RadiusChallengeSession s where s.expiresAt <= :now")
    int deleteExpired(@Param("now") Instant now);
}
