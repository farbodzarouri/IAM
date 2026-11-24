package com.authprovider.controller;

import com.authprovider.dto.ClientRequest;
import com.authprovider.dto.ClientResponse;
import com.authprovider.service.ClientService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Admin-only management of registered OAuth 2.0 machine-to-machine clients.
 */
@RestController
@RequestMapping("/v1/api/oauth-clients")
@RequiredArgsConstructor
public class OAuthClientController {

    private final ClientService clientService;

    @GetMapping({"", "/all"})
    public List<ClientResponse> getAllClients() {
        return clientService.getAllClients();
    }

    @GetMapping("/{id}")
    public ClientResponse getClientById(@PathVariable Long id) {
        return clientService.getClient(id);
    }

    @PostMapping({"", "/create"})
    public ResponseEntity<ClientResponse> createClient(@RequestBody(required = false) ClientRequest request) {
        return noStore(clientService.createClient(request));
    }

    @PutMapping("/{id}")
    public ResponseEntity<ClientResponse> updateClient(@PathVariable Long id,
                                                       @RequestBody(required = false) ClientRequest request) {
        return noStore(clientService.updateClient(id, request));
    }

    @PostMapping("/{id}/rotate-secret")
    public ResponseEntity<ClientResponse> rotateSecret(@PathVariable Long id) {
        return noStore(clientService.rotateSecret(id));
    }

    @DeleteMapping("/{id}")
    public void deleteClient(@PathVariable Long id) {
        clientService.deleteClient(id);
    }

    private static ResponseEntity<ClientResponse> noStore(ClientResponse body) {
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .header(HttpHeaders.PRAGMA, "no-cache")
                .body(body);
    }
}
