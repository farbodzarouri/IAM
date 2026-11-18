package com.authprovider.service;

import com.authprovider.entity.RadiusClient;

import java.util.List;

/**
 * Manages persisted {@link RadiusClient} definitions (IP/CIDR ranges, shared secrets, and client auth modes).
 */
public interface RadiusClientService {

    List<RadiusClient> getAllClients();

    RadiusClient getClientOrThrow(Long id);

    RadiusClient createClient(RadiusClient client);

    RadiusClient updateClient(Long id, RadiusClient updated);

    void deleteClient(Long id);
}
