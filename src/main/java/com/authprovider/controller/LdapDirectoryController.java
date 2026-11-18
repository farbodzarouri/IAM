package com.authprovider.controller;

import com.authprovider.entity.LdapDirectory;
import com.authprovider.ldap.LdapDirectoryService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/v1/api/ldap-directories")
@RequiredArgsConstructor
public class LdapDirectoryController {

    private final LdapDirectoryService service;

    @GetMapping("/all")
    public List<LdapDirectory> getAllDirectories() {
        return service.getAllDirectories();
    }

    @GetMapping("/{id}")
    public LdapDirectory getDirectoryById(@PathVariable Long id) {
        return service.getDirectoryOrThrow(id);
    }

    @PostMapping("/create")
    public LdapDirectory createDirectory(@RequestBody LdapDirectory directory) {
        return service.createDirectory(directory);
    }

    @PutMapping("/{id}")
    public LdapDirectory updateDirectory(@PathVariable Long id, @RequestBody LdapDirectory updated) {
        return service.updateDirectory(id, updated);
    }

    @DeleteMapping("/{id}")
    public void deleteDirectory(@PathVariable Long id) {
        service.deleteDirectory(id);
    }
}
