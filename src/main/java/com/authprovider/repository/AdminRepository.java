package com.authprovider.repository;

import com.authprovider.entity.Admin;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface AdminRepository extends JpaRepository<Admin, Long> {
    Optional<Admin> findByUsername(String username);

    List<Admin> findAllByUsernameIgnoreCase(String username);

    @Query("select a from Admin a where a.person.id = :personId")
    List<Admin> findByPersonId(@Param("personId") Long personId);

    @Query("select a from Admin a where a.otpToken.id = :otpTokenId")
    List<Admin> findByOtpTokenId(@Param("otpTokenId") Long otpTokenId);
}
