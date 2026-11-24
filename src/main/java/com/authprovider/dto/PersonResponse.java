package com.authprovider.dto;

import com.authprovider.entity.Person;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * Natural identity representation returned by Person and Registration APIs.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class PersonResponse {
    private Long id;
    private String firstName;
    private String lastName;
    private String displayName;
    private String email;
    private String mobile;
    private String nationalCode;
    private boolean enabled;
    private Instant createdAt;
    private Instant updatedAt;

    public static PersonResponse from(Person person) {
        if (person == null) {
            return null;
        }
        return PersonResponse.builder()
                .id(person.getId())
                .firstName(person.getFirstName())
                .lastName(person.getLastName())
                .displayName(person.getDisplayName())
                .email(person.getEmail())
                .mobile(person.getMobile())
                .nationalCode(person.getNationalCode())
                .enabled(person.isEnabled())
                .createdAt(person.getCreatedAt())
                .updatedAt(person.getUpdatedAt())
                .build();
    }
}
