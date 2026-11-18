package com.authprovider.controller;

import com.authprovider.dto.LoginResponse;
import com.authprovider.entity.LdapDirectory;
import com.authprovider.exception.BadRequestException;
import com.authprovider.exception.ConflictException;
import com.authprovider.exception.SetupAlreadyCompletedException;
import com.authprovider.service.AdminLoginService;
import com.authprovider.service.OtpProvisioningSupport;
import com.authprovider.service.QrCodeGenerator;
import com.authprovider.service.SecretGenerator;
import com.authprovider.service.SetupService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.Serializable;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

/**
 * Two-step browser login flow for {@link com.authprovider.entity.Admin} accounts.
 * Primary authentication never establishes an authenticated session directly; admins must complete
 * TOTP verification against their {@code OtpToken} (or confirm first-time enrollment) first.
 */
@Slf4j
@Controller
@RequiredArgsConstructor
public class AdminWebAuthController {

    static final String SESSION_PENDING_AUTH = "IAM_PENDING_ADMIN_AUTH";
    private static final Duration PENDING_TTL = Duration.ofSeconds(120);

    private final AdminLoginService adminLoginService;
    private final SecretGenerator secretGenerator;
    private final QrCodeGenerator qrCodeGenerator;
    private final Clock clock;
    private final SetupService setupService;
    private final SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();

    record PendingAdminAuth(Long adminId, String username, String source,
                            String pendingSecret, Instant expiresAt) implements Serializable {
    }

    @GetMapping("/setup")
    public String setupForm() {
        if (setupService == null || !setupService.isSetupRequired()) {
            return "redirect:/login";
        }
        return "setup";
    }

    @PostMapping("/setup/admin")
    public String setupLocalAdmin(@RequestParam(value = "username", required = false) String username,
                                  @RequestParam(value = "password", required = false) String password,
                                  @RequestParam(value = "displayName", required = false) String displayName,
                                  Model model) {
        if (setupService == null || !setupService.isSetupRequired()) {
            return "redirect:/login";
        }
        try {
            setupService.initializeLocalAdmin(username, password, displayName);
            return "redirect:/login?setupComplete";
        } catch (SetupAlreadyCompletedException e) {
            return "redirect:/login";
        } catch (BadRequestException | ConflictException e) {
            model.addAttribute("adminError", e.getMessage());
            return "setup";
        }
    }

    @PostMapping("/setup/ldap")
    public String setupAdminLdap(@RequestParam(value = "name", required = false) String name,
                                 @RequestParam(value = "url", required = false) String url,
                                 @RequestParam(value = "baseDn", required = false) String baseDn,
                                 @RequestParam(value = "userSearchFilter", required = false) String userSearchFilter,
                                 @RequestParam(value = "bindDn", required = false) String bindDn,
                                 @RequestParam(value = "bindPassword", required = false) String bindPassword,
                                 @RequestParam(value = "userEnabled", defaultValue = "false") boolean userEnabled,
                                 Model model) {
        if (setupService == null || !setupService.isSetupRequired()) {
            return "redirect:/login";
        }
        try {
            LdapDirectory directory = LdapDirectory.builder()
                    .name(name)
                    .url(url)
                    .baseDn(baseDn)
                    .userSearchFilter(userSearchFilter == null || userSearchFilter.isBlank()
                            ? "(&(objectClass=person)(|(uid={0})(sAMAccountName={0})))"
                            : userSearchFilter.trim())
                    .bindDn(bindDn == null || bindDn.isBlank() ? null : bindDn.trim())
                    .bindPassword(bindPassword == null || bindPassword.isBlank() ? null : bindPassword)
                    .enabled(true)
                    .userEnabled(userEnabled)
                    .adminEnabled(true)
                    .autoProvision(true)
                    .fallbackToLocal(false)
                    .build();
            setupService.initializeAdminLdap(directory);
            return "redirect:/login?setupComplete";
        } catch (SetupAlreadyCompletedException e) {
            return "redirect:/login";
        } catch (BadRequestException | ConflictException e) {
            model.addAttribute("ldapError", e.getMessage());
            return "setup";
        }
    }

    @GetMapping("/login")
    public String loginForm() {
        if (setupService != null && setupService.isSetupRequired()) {
            return "redirect:/setup";
        }
        return "login";
    }

    @PostMapping("/login")
    public String submitPrimary(@RequestParam(value = "username", required = false) String username,
                                @RequestParam(value = "password", required = false) String password,
                                HttpServletRequest request) {
        AdminLoginService.PrimaryAuthResult result = adminLoginService.verifyPrimary(username, password);
        if (result.status() == AdminLoginService.PrimaryStatus.AUTHENTICATED_NEEDS_ENROLLMENT) {
            HttpSession session = request.getSession(true);
            request.changeSessionId();
            String pendingSecret = secretGenerator.generateSecret();
            session.setAttribute(SESSION_PENDING_AUTH, new PendingAdminAuth(
                    result.adminId(), result.username(), result.source(),
                    pendingSecret, clock.instant().plus(PENDING_TTL)));
            return "redirect:/login/enroll";
        }
        if (result.status() == AdminLoginService.PrimaryStatus.AUTHENTICATED_NEEDS_OTP) {
            HttpSession session = request.getSession(true);
            request.changeSessionId();
            session.setAttribute(SESSION_PENDING_AUTH, new PendingAdminAuth(
                    result.adminId(), result.username(), result.source(),
                    null, clock.instant().plus(PENDING_TTL)));
            return "redirect:/login/otp";
        }
        return "redirect:/login?error";
    }

    @GetMapping("/login/otp")
    public String otpForm(HttpServletRequest request, Model model) {
        PendingAdminAuth pending = validPending(request, false);
        if (pending == null) {
            return "redirect:/login";
        }
        model.addAttribute("username", pending.username());
        return "admin-otp";
    }

    @PostMapping("/login/otp")
    public String submitOtp(@RequestParam(value = "otp", required = false) String otp,
                            HttpServletRequest request,
                            HttpServletResponse response,
                            Model model) {
        PendingAdminAuth pending = validPending(request, false);
        if (pending == null) {
            return "redirect:/login?expired";
        }
        LoginResponse result = adminLoginService.completeOtp(pending.adminId(), pending.source(), otp);
        if (result.isAuthenticated()) {
            establishAdminSession(pending.username(), request, response);
            return "redirect:/users";
        }
        if (result.getStatus() == LoginResponse.Status.INVALID_CREDENTIALS) {
            clearPending(request);
            return "redirect:/login?error";
        }
        model.addAttribute("username", pending.username());
        model.addAttribute("error", result.getMessage());
        return "admin-otp";
    }

    @GetMapping("/login/enroll")
    public String enrollForm(HttpServletRequest request, Model model) {
        PendingAdminAuth pending = validPending(request, true);
        if (pending == null) {
            return "redirect:/login";
        }
        populateEnrollmentModel(pending, model);
        return "admin-enroll";
    }

    @PostMapping("/login/enroll")
    public String confirmEnroll(@RequestParam(value = "otp", required = false) String otp,
                                HttpServletRequest request,
                                HttpServletResponse response,
                                Model model) {
        PendingAdminAuth pending = validPending(request, true);
        if (pending == null) {
            return "redirect:/login?expired";
        }
        LoginResponse result = adminLoginService.completeEnrollment(
                pending.adminId(), pending.source(), pending.pendingSecret(), otp);
        if (result.isAuthenticated()) {
            establishAdminSession(pending.username(), request, response);
            return "redirect:/users";
        }
        if (result.getStatus() == LoginResponse.Status.INVALID_CREDENTIALS) {
            clearPending(request);
            return "redirect:/login?error";
        }
        populateEnrollmentModel(pending, model);
        model.addAttribute("error", result.getMessage());
        return "admin-enroll";
    }

    private void populateEnrollmentModel(PendingAdminAuth pending, Model model) {
        String otpAuthUri = OtpProvisioningSupport.buildOtpAuthUri(
                qrCodeGenerator, pending.username(), pending.pendingSecret());
        model.addAttribute("username", pending.username());
        model.addAttribute("secret", pending.pendingSecret());
        model.addAttribute("otpAuthUri", otpAuthUri);
        try {
            model.addAttribute("qrCode", OtpProvisioningSupport.generateQrImage(qrCodeGenerator, otpAuthUri));
        } catch (Exception e) {
            log.error("Failed to generate admin enrollment QR code for {}", pending.username(), e);
        }
    }

    private PendingAdminAuth validPending(HttpServletRequest request, boolean enrollmentRequired) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return null;
        }
        Object raw = session.getAttribute(SESSION_PENDING_AUTH);
        if (!(raw instanceof PendingAdminAuth pending)) {
            return null;
        }
        if (!clock.instant().isBefore(pending.expiresAt())) {
            session.removeAttribute(SESSION_PENDING_AUTH);
            return null;
        }
        boolean hasPendingSecret = pending.pendingSecret() != null && !pending.pendingSecret().isBlank();
        if (hasPendingSecret != enrollmentRequired) {
            return null;
        }
        return pending;
    }

    private void clearPending(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.removeAttribute(SESSION_PENDING_AUTH);
        }
    }

    private void establishAdminSession(String username, HttpServletRequest request, HttpServletResponse response) {
        clearPending(request);
        request.getSession(true);
        request.changeSessionId();
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(new UsernamePasswordAuthenticationToken(
                username, null, List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))));
        SecurityContextHolder.setContext(context);
        securityContextRepository.saveContext(context, request, response);
    }
}
