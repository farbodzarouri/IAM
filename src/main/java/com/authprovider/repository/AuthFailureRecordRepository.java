package com.authprovider.repository;

import com.authprovider.entity.AuthFailureRecord;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;

@Repository
public interface AuthFailureRecordRepository extends JpaRepository<AuthFailureRecord, Long> {
    Optional<AuthFailureRecord> findByScopeAndSubject(String scope, String subject);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<AuthFailureRecord> findWithLockByScopeAndSubject(String scope, String subject);

    long countByScope(String scope);

    @Transactional
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("delete from AuthFailureRecord r where r.scope = :scope and r.subject = :subject")
    int deleteByScopeAndSubject(@Param("scope") String scope, @Param("subject") String subject);

    /** Removes records whose failure window has elapsed and which are not (or no longer) locked. */
    @Transactional
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("delete from AuthFailureRecord r where r.scope = :scope and r.lastFailureAt <= :windowCutoff "
            + "and (r.lockedUntil is null or r.lockedUntil <= :now)")
    int deleteExpired(@Param("scope") String scope, @Param("windowCutoff") Instant windowCutoff,
                      @Param("now") Instant now);
}
