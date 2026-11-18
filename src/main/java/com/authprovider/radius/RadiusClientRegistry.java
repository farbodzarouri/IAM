package com.authprovider.radius;

import com.authprovider.entity.AuthMode;
import com.authprovider.entity.RadiusClient;
import com.authprovider.repository.RadiusClientRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Resolves the RADIUS client (shared secret and optional per-client {@link AuthMode}) from the
 * sender's network address. Clients are persisted as {@link RadiusClient} entities; the most
 * specific active match wins (a discrete address beats a subnet, a longer prefix beats a shorter one).
 */
@Slf4j
@Component
public class RadiusClientRegistry {

    private static final int MAX_PARSED_CACHE = 10_000;

    private final RadiusClientRepository repository;
    private final String inMemorySecret;
    private final List<String> inMemoryAllowedClients;
    private final AuthMode inMemoryAuthMode;
    private final Map<String, Optional<CidrBlock>> parsedCache = new ConcurrentHashMap<>();
    private final Map<String, Set<InetAddress>> inMemoryResolved = new ConcurrentHashMap<>();

    /** Resolved client identity, shared secret, and optional authentication mode override. */
    public record ResolvedClient(Long id, String name, byte[] secret, AuthMode authMode) {
        public ResolvedClient(Long id, String name, byte[] secret) {
            this(id, name, secret, null);
        }

        @Override
        public String toString() {
            return "ResolvedClient[id=" + id + ", name=" + name + ", authMode=" + authMode + "]";
        }
    }

    @Autowired
    public RadiusClientRegistry(RadiusClientRepository repository) {
        this(repository, null, List.of(), null);
    }

    private RadiusClientRegistry(RadiusClientRepository repository,
                                 String inMemorySecret,
                                 List<String> inMemoryAllowedClients,
                                 AuthMode inMemoryAuthMode) {
        this.repository = repository;
        this.inMemorySecret = inMemorySecret;
        this.inMemoryAllowedClients = inMemoryAllowedClients == null ? List.of() : List.copyOf(inMemoryAllowedClients);
        this.inMemoryAuthMode = inMemoryAuthMode;
    }

    public static RadiusClientRegistry inMemory(String sharedSecret) {
        return inMemory(sharedSecret, List.of(), null);
    }

    public static RadiusClientRegistry inMemory(String sharedSecret, List<String> allowedClients, AuthMode authMode) {
        return new RadiusClientRegistry(null, sharedSecret, allowedClients, authMode);
    }

    public boolean isPersistent() {
        return repository != null;
    }

    /** Returns the client that may send requests from {@code address}, or empty if unauthorized. */
    public Optional<ResolvedClient> resolve(InetAddress address) {
        if (address == null) {
            return Optional.empty();
        }
        if (repository == null) {
            return resolveInMemory(address);
        }
        List<RadiusClient> clients = repository.findByActiveTrue();
        RadiusClient best = null;
        CidrBlock bestBlock = null;
        for (RadiusClient client : clients) {
            if (client == null || !client.isActive() || client.getSharedSecret() == null || client.getSharedSecret().isEmpty()) {
                continue;
            }
            Optional<CidrBlock> block = parse(client.getAddress());
            if (block.isEmpty() || !block.get().matches(address)) {
                continue;
            }
            if (best == null || isMoreSpecific(block.get(), client, bestBlock, best)) {
                best = client;
                bestBlock = block.get();
            }
        }
        if (best == null) {
            return Optional.empty();
        }
        return Optional.of(new ResolvedClient(best.getId(), best.getName(),
                best.getSharedSecret().getBytes(StandardCharsets.UTF_8), best.getAuthMode()));
    }

    /** Validates the configuration at server start-up and logs security warnings. */
    public void validate() {
        if (repository == null) {
            if (inMemorySecret == null || inMemorySecret.isEmpty()) {
                throw new IllegalStateException("In-memory RADIUS client registry requires a non-empty shared secret");
            }
            Set<InetAddress> resolved = new HashSet<>();
            for (String client : inMemoryClientEntries()) {
                resolved.addAll(resolveInMemoryEntry(client));
            }
            if (resolved.isEmpty()) {
                log.warn("RADIUS server accepts requests from any client address; consider restricting allowed clients");
            }
            return;
        }
        List<RadiusClient> clients = repository.findByActiveTrue();
        if (clients.isEmpty()) {
            log.warn("No active RADIUS clients are configured; all RADIUS requests will be dropped");
        }
        for (RadiusClient client : clients) {
            Optional<CidrBlock> block = parse(client.getAddress());
            if (block.isEmpty()) {
                log.error("RADIUS client '{}' has an invalid address '{}' and will never match",
                        client.getName(), client.getAddress());
                continue;
            }
            if (client.getSharedSecret() == null || client.getSharedSecret().isEmpty()) {
                log.error("RADIUS client '{}' has no shared secret and will never match", client.getName());
            }
            if (block.get().getPrefixLength() == 0) {
                log.warn("RADIUS client '{}' ({}) accepts requests from any address; consider restricting it",
                        client.getName(), client.getAddress());
            }
        }
    }

    private static boolean isMoreSpecific(CidrBlock candidate, RadiusClient candidateClient,
                                          CidrBlock current, RadiusClient currentClient) {
        if (candidate.getPrefixLength() != current.getPrefixLength()) {
            return candidate.getPrefixLength() > current.getPrefixLength();
        }
        Comparator<Long> ids = Comparator.nullsLast(Comparator.naturalOrder());
        return ids.compare(candidateClient.getId(), currentClient.getId()) < 0;
    }

    private Optional<CidrBlock> parse(String address) {
        if (address == null) {
            return Optional.empty();
        }
        Optional<CidrBlock> cached = parsedCache.get(address);
        if (cached != null) {
            return cached;
        }
        Optional<CidrBlock> parsed;
        try {
            parsed = Optional.of(CidrBlock.parse(address));
        } catch (IllegalArgumentException e) {
            log.warn("Ignoring RADIUS client with invalid address '{}': {}", address, e.getMessage());
            parsed = Optional.empty();
        }
        if (parsedCache.size() >= MAX_PARSED_CACHE) {
            parsedCache.clear();
        }
        parsedCache.put(address, parsed);
        return parsed;
    }

    private Optional<ResolvedClient> resolveInMemory(InetAddress address) {
        if (inMemorySecret == null || inMemorySecret.isEmpty()) {
            return Optional.empty();
        }
        List<String> entries = inMemoryClientEntries();
        byte[] secret = inMemorySecret.getBytes(StandardCharsets.UTF_8);
        if (entries.isEmpty()) {
            return Optional.of(new ResolvedClient(null, "default", secret, inMemoryAuthMode));
        }
        for (String entry : entries) {
            if (resolveInMemoryEntry(entry).contains(address)) {
                return Optional.of(new ResolvedClient(null, entry.trim(), secret, inMemoryAuthMode));
            }
            Optional<CidrBlock> block = parse(entry);
            if (block.isPresent() && block.get().matches(address)) {
                return Optional.of(new ResolvedClient(null, entry.trim(), secret, inMemoryAuthMode));
            }
        }
        return Optional.empty();
    }

    private List<String> inMemoryClientEntries() {
        return inMemoryAllowedClients.stream()
                .filter(entry -> entry != null && !entry.isBlank())
                .toList();
    }

    private Set<InetAddress> resolveInMemoryEntry(String client) {
        String key = client.trim();
        if (CidrBlock.isValid(key) && key.contains("/")) {
            return Set.of();
        }
        return inMemoryResolved.computeIfAbsent(key, entry -> {
            try {
                return Set.copyOf(Arrays.asList(InetAddress.getAllByName(entry)));
            } catch (UnknownHostException e) {
                throw new IllegalStateException("Unable to resolve RADIUS client entry: " + entry, e);
            }
        });
    }
}
