package com.authprovider.service;

import com.authprovider.dto.PersonRequest;
import com.authprovider.entity.OtpToken;
import com.authprovider.entity.Person;

import java.util.List;

/**
 * Manages {@link Person} identities and the {@link OtpToken} second-factor generators they own.
 */
public interface PersonService {

    List<Person> getAllPersons();

    Person getPersonById(Long id);

    Person getPersonOrThrow(Long id);

    Person createPerson(Person person);

    Person createPerson(PersonRequest request);

    Person updatePerson(Long id, Person updated);

    Person updatePerson(Long id, PersonRequest request);

    void deletePerson(Long id);

    OtpToken createToken(Long personId, String label, String secret);

    List<OtpToken> getTokensForPerson(Long personId);

    OtpToken getTokenById(Long tokenId);

    OtpToken getTokenOrThrow(Long tokenId);

    OtpToken rotateTokenSecret(Long tokenId);

    void setTokenEnabled(Long tokenId, boolean enabled);
}
