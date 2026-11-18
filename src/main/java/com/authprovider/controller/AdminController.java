package com.authprovider.controller;

import com.authprovider.dto.AdminRequest;
import com.authprovider.dto.AdminResponse;
import com.authprovider.service.AdminService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/v1/api/admins")
@RequiredArgsConstructor
public class AdminController {

    private final AdminService adminService;

    @GetMapping("/all")
    public List<AdminResponse> getAllAdmins() {
        return adminService.getAllAdmins().stream()
                .map(AdminResponse::from)
                .toList();
    }

    @GetMapping("/{id}")
    public AdminResponse getAdminById(@PathVariable Long id) {
        return AdminResponse.from(adminService.getAdminOrThrow(id));
    }

    @PostMapping("/create")
    public AdminResponse createAdmin(@RequestBody AdminRequest request) {
        return AdminResponse.from(adminService.createAdmin(request));
    }

    @PutMapping("/{id}")
    public AdminResponse updateAdmin(@PathVariable Long id, @RequestBody AdminRequest request) {
        return AdminResponse.from(adminService.updateAdmin(id, request));
    }

    @DeleteMapping("/{id}")
    public void deleteAdmin(@PathVariable Long id) {
        adminService.deleteAdmin(id);
    }
}
