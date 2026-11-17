package com.authprovider.repository;

import com.authprovider.entity.OtpReplayState;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

@Repository
public interface OtpReplayStateRepository extends JpaRepository<OtpReplayState, Long> {

    boolean existsByUserId(Long userId);

    /**
     * Atomically advances the user's last accepted time step; returns 1 only if {@code step} is strictly
     * greater than the stored value (the row is locked by the database for the duration of the update).
     */
    @Transactional
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("update OtpReplayState s set s.lastTimeStep = :step, s.updatedAt = :now "
            + "where s.userId = :userId and s.lastTimeStep < :step")
    int advance(@Param("userId") Long userId, @Param("step") long step, @Param("now") Instant now);

    @Transactional
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("delete from OtpReplayState s where s.userId = :userId")
    int deleteByUserId(@Param("userId") Long userId);
}
