package com.authprovider.repository;

import com.authprovider.entity.LdapDirectory;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface LdapDirectoryRepository extends JpaRepository<LdapDirectory, Long> {
    List<LdapDirectory> findByEnabledTrueOrderByPriorityAscIdAsc();

    List<LdapDirectory> findAllByOrderByPriorityAscIdAsc();

    Optional<LdapDirectory> findByName(String name);
}
