package com.authprovider.controller;

import com.authprovider.dto.AdminResponse;
import com.authprovider.entity.LdapDirectory;
import com.authprovider.exception.BadRequestException;
import com.authprovider.service.SetupService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/v1/api/setup")
@RequiredArgsConstructor
public class SetupController {

    private final SetupService setupService;

    public record LocalAdminSetupRequest(String username, String password, String displayName) {
    }

    @GetMapping("/status")
    public Map<String, Boolean> status() {
        return Map.of("setupRequired", setupService.isSetupRequired());
    }

    @PostMapping("/admin")
    public AdminResponse initializeLocalAdmin(@RequestBody(required = false) LocalAdminSetupRequest request) {
        if (request == null) {
            throw new BadRequestException("Admin setup payload is required");
        }
        return AdminResponse.from(setupService.initializeLocalAdmin(
                request.username(), request.password(), request.displayName()));
    }

    @PostMapping("/ldap")
    public LdapDirectory initializeAdminLdap(@RequestBody(required = false) LdapDirectory directory) {
        return setupService.initializeAdminLdap(directory);
    }
}
