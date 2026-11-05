package com.authprovider.radius;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.SmartLifecycle;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static com.authprovider.radius.RadiusConstants.*;

@Slf4j
@Component
public class RadiusServer implements SmartLifecycle {

    private static final long HOUSEKEEPING_INTERVAL_SECONDS = 5;

    private final RadiusProperties properties;
    private final RadiusAuthenticationHandler handler;
    private final RadiusChallengeStore challengeStore;
    private final RadiusAuthGuard authGuard;
    private final Clock clock;
    private final Map<String, CachedResponse> responseCache = new ConcurrentHashMap<>();

    private volatile boolean running;
    private volatile DatagramSocket socket;
    private Thread receiver;
    private ThreadPoolExecutor workers;
    private ScheduledExecutorService housekeeping;
    private Set<InetAddress> allowedClients = Set.of();

    public RadiusServer(RadiusProperties properties, RadiusAuthenticationHandler handler,
                        RadiusChallengeStore challengeStore, RadiusAuthGuard authGuard, Clock clock) {
        this.properties = properties;
        this.handler = handler;
        this.challengeStore = challengeStore;
        this.authGuard = authGuard;
        this.clock = clock;
    }

    private static final class CachedResponse {
        private final int identifier;
        private final byte[] fingerprint;
        private final Instant expiresAt;
        private final CountDownLatch ready = new CountDownLatch(1);
        private volatile byte[] response;

        private CachedResponse(int identifier, byte[] fingerprint, Instant expiresAt) {
            this.identifier = identifier;
            this.fingerprint = fingerprint;
            this.expiresAt = expiresAt;
        }
    }

    @Override
    public synchronized void start() {
        if (running) {
            return;
        }
        if (!properties.isEnabled()) {
            log.info("RADIUS server disabled (radius.enabled=false)");
            return;
        }
        properties.validate();
        allowedClients = resolveAllowedClients();
        if (RadiusProperties.DEFAULT_SHARED_SECRET.equals(properties.getSharedSecret())) {
            log.warn("RADIUS server is using the default shared secret; set radius.shared-secret to a strong value in production");
        }
        if (allowedClients.isEmpty()) {
            log.warn("RADIUS server accepts requests from any client address; consider restricting radius.allowed-clients");
        }

        DatagramSocket datagramSocket;
        try {
            InetAddress bindAddress = properties.getBindAddress() == null || properties.getBindAddress().isBlank()
                    ? null : InetAddress.getByName(properties.getBindAddress().trim());
            datagramSocket = new DatagramSocket(null);
            datagramSocket.setReuseAddress(true);
            datagramSocket.bind(new InetSocketAddress(bindAddress, properties.getPort()));
        } catch (IOException e) {
            log.error("Unable to start RADIUS server on port {}: {}", properties.getPort(), e.getMessage());
            return;
        }
        socket = datagramSocket;

        AtomicInteger workerCounter = new AtomicInteger();
        workers = new ThreadPoolExecutor(properties.getWorkerThreads(), properties.getWorkerThreads(),
                0L, TimeUnit.MILLISECONDS, new ArrayBlockingQueue<>(properties.getWorkerQueueCapacity()),
                runnable -> daemon(runnable, "radius-worker-" + workerCounter.incrementAndGet()),
                new ThreadPoolExecutor.AbortPolicy());
        housekeeping = Executors.newSingleThreadScheduledExecutor(runnable -> daemon(runnable, "radius-housekeeping"));
        housekeeping.scheduleWithFixedDelay(this::housekeep, HOUSEKEEPING_INTERVAL_SECONDS,
                HOUSEKEEPING_INTERVAL_SECONDS, TimeUnit.SECONDS);

        running = true;
        receiver = daemon(this::receiveLoop, "radius-receiver");
        receiver.start();
        log.info("RADIUS server listening on {}:{} (challenge TTL {}s)",
                socket.getLocalAddress().getHostAddress(), socket.getLocalPort(), properties.getChallenge().getTtlSeconds());
    }

    @Override
    public synchronized void stop() {
        if (!running) {
            return;
        }
        running = false;
        DatagramSocket current = socket;
        if (current != null) {
            current.close();
        }
        if (receiver != null) {
            try {
                receiver.join(TimeUnit.SECONDS.toMillis(5));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        if (workers != null) {
            workers.shutdown();
            try {
                if (!workers.awaitTermination(5, TimeUnit.SECONDS)) {
                    workers.shutdownNow();
                }
            } catch (InterruptedException e) {
                workers.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
        if (housekeeping != null) {
            housekeeping.shutdownNow();
        }
        responseCache.clear();
        log.info("RADIUS server stopped");
    }

    @Override
    public boolean isRunning() {
        return running;
    }

    public int getLocalPort() {
        DatagramSocket current = socket;
        return current == null ? -1 : current.getLocalPort();
    }

    private void receiveLoop() {
        byte[] buffer = new byte[MAX_PACKET_LENGTH];
        while (running) {
            DatagramPacket datagram = new DatagramPacket(buffer, buffer.length);
            try {
                socket.receive(datagram);
            } catch (SocketException e) {
                if (running) {
                    log.error("RADIUS socket error", e);
                }
                break;
            } catch (IOException e) {
                log.warn("RADIUS receive failed: {}", e.getMessage());
                continue;
            }
            byte[] data = Arrays.copyOfRange(datagram.getData(), datagram.getOffset(),
                    datagram.getOffset() + datagram.getLength());
            InetSocketAddress source = (InetSocketAddress) datagram.getSocketAddress();
            try {
                workers.execute(() -> process(data, source));
            } catch (RejectedExecutionException e) {
                log.warn("RADIUS worker queue full; dropping request from {}", source.getAddress().getHostAddress());
            }
        }
    }

    void process(byte[] data, InetSocketAddress source) {
        InetAddress address = source.getAddress();
        if (!allowedClients.isEmpty() && !allowedClients.contains(address)) {
            log.warn("Dropping RADIUS packet from unauthorized client {}", address.getHostAddress());
            return;
        }
        RadiusPacket packet;
        try {
            packet = RadiusPacket.decode(data, data.length);
        } catch (RadiusException e) {
            log.debug("Dropping malformed RADIUS packet from {}: {}", address.getHostAddress(), e.getMessage());
            return;
        }
        if (packet.getCode() == STATUS_SERVER) {
            handleSafely(packet, source).ifPresent(response -> send(response, source));
            return;
        }
        if (packet.getCode() != ACCESS_REQUEST) {
            log.debug("Dropping RADIUS packet with unsupported code {} from {}", packet.getCode(), address.getHostAddress());
            return;
        }

        String key = address.getHostAddress() + "|"
                + Base64.getEncoder().encodeToString(packet.getAuthenticator());
        byte[] fingerprint = sha256(packet.getRawBytes());
        Instant now = clock.instant();
        CachedResponse entry = new CachedResponse(packet.getIdentifier(), fingerprint,
                now.plus(Duration.ofSeconds(properties.getDuplicateCacheSeconds())));

        CachedResponse existing = responseCache.get(key);
        if (existing != null && now.isBefore(existing.expiresAt)) {
            replayCached(existing, packet.getIdentifier(), fingerprint, source);
            return;
        }
        if (responseCache.size() >= properties.getMaxDuplicateCacheEntries()) {
            purgeResponseCache();
            if (responseCache.size() >= properties.getMaxDuplicateCacheEntries()) {
                log.warn("RADIUS duplicate cache full; dropping request from {}", address.getHostAddress());
                return;
            }
        }
        boolean claimed = existing == null
                ? responseCache.putIfAbsent(key, entry) == null
                : responseCache.replace(key, existing, entry);
        if (!claimed) {
            CachedResponse winner = responseCache.get(key);
            if (winner != null) {
                replayCached(winner, packet.getIdentifier(), fingerprint, source);
            }
            return;
        }

        try {
            Optional<byte[]> response = handleSafely(packet, source);
            if (response.isEmpty()) {
                responseCache.remove(key, entry);
                return;
            }
            entry.response = response.get();
            send(entry.response, source);
        } finally {
            entry.ready.countDown();
        }
    }

    private void replayCached(CachedResponse cached, int identifier, byte[] fingerprint, InetSocketAddress source) {
        if (cached.identifier != identifier || !MessageDigest.isEqual(cached.fingerprint, fingerprint)) {
            log.warn("Dropping RADIUS packet from {} reusing Request Authenticator with different identifier or content",
                    source.getAddress().getHostAddress());
            return;
        }
        try {
            cached.ready.await(1, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return;
        }
        byte[] response = cached.response;
        if (response != null) {
            log.debug("Retransmitting cached RADIUS response for identifier {} to {}", identifier, source);
            send(response, source);
        }
    }

    private Optional<byte[]> handleSafely(RadiusPacket packet, InetSocketAddress source) {
        try {
            return handler.handle(packet, source.getAddress());
        } catch (Exception e) {
            log.error("Error processing RADIUS request from {}; request discarded", source.getAddress().getHostAddress(), e);
            return Optional.empty();
        }
    }

    private void send(byte[] response, InetSocketAddress destination) {
        DatagramSocket current = socket;
        if (current == null || current.isClosed()) {
            return;
        }
        try {
            current.send(new DatagramPacket(response, response.length, destination));
        } catch (IOException e) {
            log.warn("Failed to send RADIUS response to {}: {}", destination, e.getMessage());
        }
    }

    private void housekeep() {
        try {
            purgeResponseCache();
            challengeStore.purgeExpired();
            authGuard.purgeExpired();
        } catch (Exception e) {
            log.warn("RADIUS housekeeping failed", e);
        }
    }

    private void purgeResponseCache() {
        Instant now = clock.instant();
        responseCache.values().removeIf(cached -> !now.isBefore(cached.expiresAt));
    }

    private Set<InetAddress> resolveAllowedClients() {
        Set<InetAddress> resolved = new HashSet<>();
        if (properties.getAllowedClients() == null) {
            return resolved;
        }
        for (String client : properties.getAllowedClients()) {
            if (client == null || client.isBlank()) {
                continue;
            }
            try {
                resolved.addAll(Arrays.asList(InetAddress.getAllByName(client.trim())));
            } catch (UnknownHostException e) {
                throw new IllegalStateException("Unable to resolve radius.allowed-clients entry: " + client, e);
            }
        }
        return Set.copyOf(resolved);
    }

    private static Thread daemon(Runnable runnable, String name) {
        Thread thread = new Thread(runnable, name);
        thread.setDaemon(true);
        return thread;
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
