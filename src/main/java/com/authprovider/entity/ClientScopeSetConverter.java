package com.authprovider.entity;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Persists a scope set as an RFC 6749 space-delimited scope string in a single column.
 */
@Converter
public class ClientScopeSetConverter implements AttributeConverter<Set<ClientScope>, String> {

    @Override
    public String convertToDatabaseColumn(Set<ClientScope> scopes) {
        if (scopes == null || scopes.isEmpty()) {
            return "";
        }
        return EnumSet.copyOf(scopes).stream().map(ClientScope::value).collect(Collectors.joining(" "));
    }

    @Override
    public Set<ClientScope> convertToEntityAttribute(String column) {
        EnumSet<ClientScope> scopes = EnumSet.noneOf(ClientScope.class);
        if (column != null) {
            for (String token : column.trim().split(" +")) {
                ClientScope.find(token).ifPresent(scopes::add);
            }
        }
        return Collections.unmodifiableSet(scopes);
    }
}
