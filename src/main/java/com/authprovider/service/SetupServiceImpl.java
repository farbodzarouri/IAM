package com.authprovider.service;

import com.authprovider.dto.AdminRequest;
import com.authprovider.entity.Admin;
import com.authprovider.entity.LdapDirectory;
import com.authprovider.exception.BadRequestException;
import com.authprovider.exception.SetupAlreadyCompletedException;
import com.authprovider.ldap.LdapDirectoryService;
import com.authprovider.repository.AdminRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Default implementation of {@link SetupService}.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class SetupServiceImpl implements SetupService {

    private final AdminRepository adminRepository;
    private final AdminService adminService;
    private final LdapDirectoryService ldapDirectoryService;

    @Override
    @Transactional(readOnly = true)
    public boolean isSetupRequired() {
        return adminRepository.count() == 0 && ldapDirectoryService.enabledAdminDirectories().isEmpty();
    }

    @Override
    @Transactional
    public synchronized Admin initializeLocalAdmin(String username, String password, String displayName) {
        ensureSetupRequired();
        String trimmedUser = username == null ? "" : username.trim();
        if (trimmedUser.isEmpty()) {
            throw new BadRequestException("Admin username is required");
        }
        if (password == null || password.isBlank()) {
            throw new BadRequestException("Admin password is required");
        }
        Admin saved = adminService.createAdmin(AdminRequest.builder()
                .username(trimmedUser)
                .password(password)
                .displayName(displayName)
                .enabled(true)
                .build());
        log.info("Completed first-run setup by creating initial local admin '{}'", trimmedUser);
        return saved;
    }

    @Override
    @Transactional
    public synchronized LdapDirectory initializeAdminLdap(LdapDirectory directory) {
        ensureSetupRequired();
        if (directory == null) {
            throw new BadRequestException("LDAP directory configuration is required");
        }
        if (directory.getName() == null || directory.getName().isBlank()) {
            directory.setName("admin-ldap");
        }
        directory.setEnabled(true);
        directory.setAdminEnabled(true);
        LdapDirectory saved = ldapDirectoryService.createDirectory(directory);
        log.info("Completed first-run setup by configuring initial Admin LDAP directory '{}'", saved.getName());
        return saved;
    }

    private void ensureSetupRequired() {
        if (!isSetupRequired()) {
            throw new SetupAlreadyCompletedException("Initial setup has already been completed");
        }
    }
}
