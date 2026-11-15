package com.authprovider.repository;

import com.authprovider.entity.MfaApproval;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;

@Repository
public interface MfaApprovalRepository extends JpaRepository<MfaApproval, Long> {
    Optional<MfaApproval> findByUsername(String username);

    /** Atomically consumes the approval; returns 1 only for the single caller that removed it. */
    @Transactional
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("delete from MfaApproval a where a.id = :id")
    int deleteByIdReturningCount(@Param("id") Long id);

    @Transactional
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("delete from MfaApproval a where a.username = :username")
    int deleteByUsername(@Param("username") String username);

    @Transactional
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("delete from MfaApproval a where a.expiresAt <= :now")
    int deleteExpired(@Param("now") Instant now);
}
