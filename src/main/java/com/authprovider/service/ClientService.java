package com.authprovider.service;

import com.authprovider.dto.ClientRequest;
import com.authprovider.dto.ClientResponse;

import java.util.List;

/**
 * Manages registered OAuth 2.0 machine-to-machine clients ({@code clients} table).
 */
public interface ClientService {

    List<ClientResponse> getAllClients();

    ClientResponse getClient(Long id);

    /** Registers a client; a random client id / secret is generated when omitted and returned once. */
    ClientResponse createClient(ClientRequest request);

    /** Partially updates a client; a supplied secret rotates the secret, {@code blocked=false} clears lockouts. */
    ClientResponse updateClient(Long id, ClientRequest request);

    /** Replaces the client secret with a newly generated one (returned once). */
    ClientResponse rotateSecret(Long id);

    void deleteClient(Long id);
}
