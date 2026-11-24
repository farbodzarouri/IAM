package com.authprovider.repository;

import com.authprovider.entity.OtpToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface OtpTokenRepository extends JpaRepository<OtpToken, Long> {
    @Query("select t from OtpToken t where t.person.id = :personId")
    List<OtpToken> findByPersonId(@Param("personId") Long personId);

    /** The persisted secret of a token, read as a scalar independent of any (modified) managed instance. */
    @Query("select t.secret from OtpToken t where t.id = :id")
    Optional<String> findSecretById(@Param("id") Long id);
}
