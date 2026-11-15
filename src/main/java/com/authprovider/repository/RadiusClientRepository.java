package com.authprovider.repository;

import com.authprovider.entity.RadiusClient;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface RadiusClientRepository extends JpaRepository<RadiusClient, Long> {
    List<RadiusClient> findByActiveTrue();

    Optional<RadiusClient> findByName(String name);

    List<RadiusClient> findByAddress(String address);
}
