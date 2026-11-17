package com.authprovider.repository;

import com.authprovider.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);

    List<User> findAllByUsernameIgnoreCase(String username);

    /**
     * Returns the persisted (username, password, secret) of a user as scalar values, independent of any
     * (possibly modified) managed entity instance, so credential changes can be detected on save.
     */
    @Query("select u.username, u.password, u.secret from User u where u.id = :id")
    List<Object[]> findCredentialSnapshot(@Param("id") Long id);
}
