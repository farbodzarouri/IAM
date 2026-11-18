package com.authprovider.service;

import com.authprovider.entity.Admin;
import com.authprovider.repository.AdminRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Loads {@link Admin} principals for Spring Security so the framework never falls back to a generated
 * default password. Interactive logins still require two-factor verification via
 * {@link AdminLoginService}.
 */
@Service
@RequiredArgsConstructor
public class IamAdminUserDetailsService implements UserDetailsService {

    private final AdminRepository adminRepository;
    private final AccountLockoutService lockoutService;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if (username == null || username.isBlank()) {
            throw new UsernameNotFoundException("Empty username");
        }
        List<Admin> matches = adminRepository.findAllByUsernameIgnoreCase(username.trim());
        if (matches.size() != 1) {
            throw new UsernameNotFoundException("Admin not found: " + username);
        }
        Admin admin = matches.get(0);
        boolean unlocked = !lockoutService.isAdminLocked(admin.getId())
                && (admin.getOtpToken() == null || !lockoutService.isTokenLocked(admin.getOtpToken().getId()));
        return User.withUsername(admin.getUsername())
                .password(admin.getPassword() == null ? "" : admin.getPassword())
                .authorities("ROLE_ADMIN")
                .disabled(!admin.isAccountEnabled())
                .accountLocked(!unlocked)
                .build();
    }
}
