package com.authprovider.controller;

import com.authprovider.entity.RadiusClient;
import com.authprovider.service.RadiusClientService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/v1/api/radius-clients")
@RequiredArgsConstructor
public class RadiusClientController {

    private final RadiusClientService service;

    @GetMapping("/all")
    public List<RadiusClient> getAllClients() {
        return service.getAllClients();
    }

    @GetMapping("/{id}")
    public RadiusClient getClientById(@PathVariable Long id) {
        return service.getClientOrThrow(id);
    }

    @PostMapping("/create")
    public RadiusClient createClient(@RequestBody RadiusClient client) {
        return service.createClient(client);
    }

    @PutMapping("/{id}")
    public RadiusClient updateClient(@PathVariable Long id, @RequestBody RadiusClient updated) {
        return service.updateClient(id, updated);
    }

    @DeleteMapping("/{id}")
    public void deleteClient(@PathVariable Long id) {
        service.deleteClient(id);
    }
}
