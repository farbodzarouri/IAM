package com.authprovider.repository;

import com.authprovider.entity.OAuthRevokedToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

@Repository
public interface OAuthRevokedTokenRepository extends JpaRepository<OAuthRevokedToken, Long> {
    boolean existsByJti(String jti);

    @Transactional
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("delete from OAuthRevokedToken t where t.expiresAt <= :now")
    int deleteExpired(@Param("now") Instant now);
}
