package com.authprovider.repository;

import com.authprovider.entity.UserOAuthClient;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

@Repository
public interface UserOAuthClientRepository extends JpaRepository<UserOAuthClient, Long> {

    @Query("select a from UserOAuthClient a join fetch a.client where a.user.id = :userId order by a.client.id")
    List<UserOAuthClient> findByUserId(@Param("userId") Long userId);

    @Query("select a from UserOAuthClient a join fetch a.client where a.user.id in :userIds order by a.user.id, a.client.id")
    List<UserOAuthClient> findByUserIdIn(@Param("userIds") Collection<Long> userIds);

    @Query("select a from UserOAuthClient a join fetch a.client where a.user.id = :userId and a.client.id = :clientId")
    Optional<UserOAuthClient> findByUserIdAndClientId(@Param("userId") Long userId, @Param("clientId") Long clientId);

    @Transactional
    @Modifying(flushAutomatically = true)
    @Query("delete from UserOAuthClient a where a.user.id = :userId")
    int deleteByUserId(@Param("userId") Long userId);

    @Transactional
    @Modifying(flushAutomatically = true)
    @Query("delete from UserOAuthClient a where a.client.id = :clientId")
    int deleteByClientId(@Param("clientId") Long clientId);
}
