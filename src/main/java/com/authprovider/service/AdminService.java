package com.authprovider.service;

import com.authprovider.dto.AdminRequest;
import com.authprovider.entity.Admin;

import java.util.List;

/**
 * Manages {@link Admin} accounts, linking them to {@link com.authprovider.entity.Person} identities
 * and {@link com.authprovider.entity.OtpToken} generators while enforcing separate primary credentials
 * from any {@link com.authprovider.entity.User} of the same person.
 */
public interface AdminService {

    List<Admin> getAllAdmins();

    Admin getAdminById(Long id);

    Admin getAdminOrThrow(Long id);

    List<Admin> findAllByUsernameIgnoreCase(String username);

    Admin createAdmin(AdminRequest request);

    Admin updateAdmin(Long id, AdminRequest request);

    Admin saveAdmin(Admin admin);

    void deleteAdmin(Long id);
}
