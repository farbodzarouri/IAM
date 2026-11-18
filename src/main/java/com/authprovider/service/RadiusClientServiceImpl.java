package com.authprovider.service;

import com.authprovider.entity.RadiusClient;
import com.authprovider.exception.BadRequestException;
import com.authprovider.exception.ConflictException;
import com.authprovider.exception.ResourceNotFoundException;
import com.authprovider.radius.CidrBlock;
import com.authprovider.repository.RadiusClientRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Objects;

/**
 * Default implementation of {@link RadiusClientService}.
 */
@Service
@RequiredArgsConstructor
public class RadiusClientServiceImpl implements RadiusClientService {

    private final RadiusClientRepository repository;

    @Override
    public List<RadiusClient> getAllClients() {
        return repository.findAll();
    }

    @Override
    public RadiusClient getClientOrThrow(Long id) {
        if (id == null) {
            throw new ResourceNotFoundException("RADIUS client not found: null");
        }
        return repository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("RADIUS client not found: " + id));
    }

    @Override
    @Transactional
    public RadiusClient createClient(RadiusClient client) {
        if (client == null) {
            throw new BadRequestException("RADIUS client payload is required");
        }
        client.setId(null);
        normalizeAndValidate(client);
        if (client.getSharedSecret() == null || client.getSharedSecret().isEmpty()) {
            throw new BadRequestException("sharedSecret must not be empty");
        }
        if (repository.findByName(client.getName()).isPresent()) {
            throw new ConflictException("RADIUS client already exists: " + client.getName());
        }
        return repository.saveAndFlush(client);
    }

    @Override
    @Transactional
    public RadiusClient updateClient(Long id, RadiusClient updated) {
        RadiusClient existing = getClientOrThrow(id);
        if (updated == null) {
            throw new BadRequestException("RADIUS client payload is required");
        }
        normalizeAndValidate(updated);
        String name = updated.getName();
        repository.findByName(name).ifPresent(other -> {
            if (!Objects.equals(other.getId(), id)) {
                throw new ConflictException("RADIUS client already exists: " + name);
            }
        });
        existing.setName(name);
        existing.setAddress(updated.getAddress());
        if (updated.getSharedSecret() != null && !updated.getSharedSecret().isEmpty()) {
            existing.setSharedSecret(updated.getSharedSecret());
        }
        existing.setActive(updated.isActive());
        existing.setAuthMode(updated.getAuthMode());
        existing.setDescription(updated.getDescription());
        return repository.saveAndFlush(existing);
    }

    @Override
    @Transactional
    public void deleteClient(Long id) {
        RadiusClient existing = getClientOrThrow(id);
        repository.delete(existing);
    }

    private static void normalizeAndValidate(RadiusClient client) {
        String name = client.getName() == null ? "" : client.getName().trim();
        String address = client.getAddress() == null ? "" : client.getAddress().trim();
        if (name.isEmpty()) {
            throw new BadRequestException("RADIUS client name is required");
        }
        if (!CidrBlock.isValid(address)) {
            throw new BadRequestException("Invalid IP or CIDR address: " + address);
        }
        client.setName(name);
        client.setAddress(address);
    }
}
