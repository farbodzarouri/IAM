package com.authprovider.repository;

import com.authprovider.entity.OAuthSigningKey;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;

@Repository
public interface OAuthSigningKeyRepository extends JpaRepository<OAuthSigningKey, Long> {
    List<OAuthSigningKey> findByVerifyUntilAfterOrderBySignFromDescIdDesc(Instant now);

    @Transactional
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("delete from OAuthSigningKey k where k.verifyUntil <= :now")
    int deleteExpired(@Param("now") Instant now);
}
