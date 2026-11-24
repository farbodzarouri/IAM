package com.authprovider.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Natural identity profile payload. When {@code displayName} is omitted or blank,
 * it is derived automatically from {@code firstName} and {@code lastName}.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PersonRequest {
    private String firstName;
    private String lastName;
    private String displayName;
    private String email;
    private String mobile;
    private String nationalCode;
    private Boolean enabled;
}
