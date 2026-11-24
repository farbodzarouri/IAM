package com.authprovider.controller;

import com.authprovider.dto.ClientSummaryResponse;
import com.authprovider.entity.ClientType;
import com.authprovider.exception.BadRequestException;
import com.authprovider.service.UserClientAssignmentService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Locale;

/**
 * Admin-only, type-independent listing of all clients (RADIUS and OAuth 2.0) users can be assigned to.
 * Never returns secrets. Type-specific management lives at {@code /v1/api/radius-clients} and
 * {@code /v1/api/oauth-clients}.
 */
@RestController
@RequestMapping("/v1/api/clients")
@RequiredArgsConstructor
public class ClientController {

    private final UserClientAssignmentService assignmentService;

    @GetMapping({"", "/all"})
    public List<ClientSummaryResponse> getAllClients(@RequestParam(value = "type", required = false) String type) {
        return assignmentService.listClients(parseType(type));
    }

    private static ClientType parseType(String type) {
        if (type == null || type.isBlank()) {
            return null;
        }
        try {
            return ClientType.valueOf(type.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            throw new BadRequestException("Invalid client type: " + type + " (expected RADIUS or OAUTH2)");
        }
    }
}
