package com.authprovider.repository;

import com.authprovider.entity.Person;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface PersonRepository extends JpaRepository<Person, Long> {

    Optional<Person> findByEmailIgnoreCase(String email);

    Optional<Person> findByMobile(String mobile);

    Optional<Person> findByNationalCodeIgnoreCase(String nationalCode);
}
