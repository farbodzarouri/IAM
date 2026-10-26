package com.authprovider.radius;

import com.authprovider.service.MfaPreAuthService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.SmartLifecycle;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * RADIUS authentication server (RFC 2865 / RFC 3579) used as the MFA back-end for
 * Windows NPS acting as a RADIUS proxy for Remote Desktop Gateway.
 * <p>
 * Every Access-Request must carry a valid Message-Authenticator (RFC 3579, BlastRADIUS mitigation).
 * The request is accepted only if the user holds an active, unconsumed MFA pre-authentication
 * approval, which is consumed atomically. Retransmissions (same client, port, identifier and
 * Request Authenticator) are answered with the cached reply so they never consume a second approval
 * nor flip an Accept into a Reject; replays of a known Request Authenticator from a different
 * port/identifier are silently discarded.
 */
@Slf4j
@Component
public class RadiusServer implements SmartLifecycle {

    private static final int SOCKET_TIMEOUT_MS = 1000;
    private static final int MAX_CACHE_ENTRIES = 100_000;
    private static final Duration MIN_DUPLICATE_WINDOW = Duration.ofSeconds(30);

    private final MfaPreAuthService mfaPreAuthService;
    private final Clock clock;
    private final String bindAddress;
    private final int port;
    private final byte[] sharedSecret;
    private final Set<InetAddress> allowedClients;
    private final Duration duplicateWindow;

    /** key: client IP + Request Authenticator, insertion-ordered for cheap expiry. */
    private final Map<String, CachedResponse> responseCache = new LinkedHashMap<>();

    private volatile DatagramSocket socket;
    private volatile Thread worker;
    private volatile boolean running;

    private record CachedResponse(int sourcePort, int identifier, byte[] response, Instant expires) {
    }

    public RadiusServer(MfaPreAuthService mfaPreAuthService,
                        Clock clock,
                        @Value("${radius.port:1812}") int port,
                        @Value("${radius.shared-secret:secret}") String sharedSecret,
                        @Value("${radius.mfa.ttl-seconds:60}") long ttlSeconds,
                        @Value("${radius.bind-address:0.0.0.0}") String bindAddress,
                        @Value("${radius.allowed-clients:}") String allowedClients) {
        if (port < 0 || port > 65535) {
            throw new IllegalArgumentException("radius.port out of range: " + port);
        }
        if (sharedSecret == null || sharedSecret.isEmpty()) {
            throw new IllegalArgumentException("radius.shared-secret must not be empty");
        }
        if (ttlSeconds <= 0) {
            throw new IllegalArgumentException("radius.mfa.ttl-seconds must be positive");
        }
        this.mfaPreAuthService = mfaPreAuthService;
        this.clock = clock;
        this.port = port;
        this.bindAddress = bindAddress;
        this.sharedSecret = sharedSecret.getBytes(StandardCharsets.UTF_8);
        this.allowedClients = parseClients(allowedClients);
        Duration ttl = Duration.ofSeconds(ttlSeconds);
        this.duplicateWindow = ttl.compareTo(MIN_DUPLICATE_WINDOW) > 0 ? ttl : MIN_DUPLICATE_WINDOW;
        if ("secret".equals(sharedSecret)) {
            log.warn("RADIUS is using the default shared secret; set radius.shared-secret to a strong value in production");
        }
    }

    private static Set<InetAddress> parseClients(String value) {
        if (value == null || value.isBlank()) {
            return Set.of();
        }
        return Arrays.stream(value.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .map(s -> {
                    try {
                        return InetAddress.getByName(s);
                    } catch (UnknownHostException e) {
                        throw new IllegalArgumentException("Invalid radius.allowed-clients entry: " + s, e);
                    }
                })
                .collect(Collectors.toUnmodifiableSet());
    }

    // ---------------------------------------------------------------- lifecycle

    @Override
    public synchronized void start() {
        if (running) {
            return;
        }
        try {
            DatagramSocket s = new DatagramSocket(null);
            s.setReuseAddress(true);
            s.bind(new InetSocketAddress(InetAddress.getByName(bindAddress), port));
            s.setSoTimeout(SOCKET_TIMEOUT_MS);
            socket = s;
        } catch (IOException e) {
            log.error("Unable to start RADIUS server on {}:{} - RADIUS MFA will be unavailable", bindAddress, port, e);
            return;
        }
        running = true;
        Thread t = new Thread(this::serve, "radius-server-" + getLocalPort());
        t.setDaemon(true);
        worker = t;
        t.start();
        log.info("RADIUS server listening on {}:{}", bindAddress, getLocalPort());
    }

    @Override
    public synchronized void stop() {
        running = false;
        DatagramSocket s = socket;
        if (s != null) {
            s.close();
        }
        Thread t = worker;
        if (t != null && t != Thread.currentThread()) {
            try {
                t.join(SOCKET_TIMEOUT_MS * 2L);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        worker = null;
        socket = null;
        synchronized (responseCache) {
            responseCache.clear();
        }
        log.info("RADIUS server stopped");
    }

    @Override
    public boolean isRunning() {
        return running;
    }

    /** @return the bound UDP port (useful when radius.port=0), or -1 if not running. */
    public int getLocalPort() {
        DatagramSocket s = socket;
        return s == null ? -1 : s.getLocalPort();
    }

    // ---------------------------------------------------------------- serving

    private void serve() {
        byte[] buffer = new byte[RadiusPacket.MAX_LENGTH];
        while (running) {
            DatagramSocket s = socket;
            if (s == null) {
                break;
            }
            DatagramPacket datagram = new DatagramPacket(buffer, buffer.length);
            try {
                s.receive(datagram);
            } catch (SocketTimeoutException e) {
                purgeExpired(clock.instant());
                continue;
            } catch (SocketException e) {
                if (running) {
                    log.error("RADIUS socket error", e);
                }
                break;
            } catch (IOException e) {
                log.warn("RADIUS receive failed", e);
                continue;
            }
            try {
                byte[] response = handle(datagram.getData(), datagram.getOffset(), datagram.getLength(),
                        datagram.getAddress(), datagram.getPort());
                if (response != null) {
                    s.send(new DatagramPacket(response, response.length, datagram.getAddress(), datagram.getPort()));
                }
            } catch (Exception e) {
                // Never let a single bad packet terminate the server.
                log.warn("Failed to process RADIUS packet from {}", datagram.getAddress(), e);
            }
        }
    }

    /**
     * Processes one datagram and returns the encoded reply, or null if the packet must be
     * silently discarded.
     */
    byte[] handle(byte[] data, int offset, int length, InetAddress source, int sourcePort) {
        if (!allowedClients.isEmpty() && !allowedClients.contains(source)) {
            log.warn("Discarding RADIUS packet from unauthorised client {}", source.getHostAddress());
            return null;
        }
        RadiusPacket request;
        try {
            request = RadiusPacket.decode(data, offset, length);
        } catch (IllegalArgumentException e) {
            log.warn("Discarding malformed RADIUS packet from {}: {}", source.getHostAddress(), e.getMessage());
            return null;
        }
        if (request.getCode() != RadiusPacket.ACCESS_REQUEST) {
            log.debug("Discarding RADIUS packet with unsupported code {} from {}", request.getCode(), source.getHostAddress());
            return null;
        }
        if (request.hasMessageAuthenticator() && !request.verifyRequestMessageAuthenticator(sharedSecret)) {
            log.warn("Discarding Access-Request from {} with missing or invalid Message-Authenticator",
                    source.getHostAddress());
            return null;
        }

        Instant now = clock.instant();
        String cacheKey = source.getHostAddress() + '|' + HexFormat.of().formatHex(request.getAuthenticator());
        synchronized (responseCache) {
            purgeExpired(now);
            CachedResponse cached = responseCache.get(cacheKey);
            if (cached != null) {
                if (cached.identifier() == request.getIdentifier()) {
                    log.debug("Retransmitted Access-Request id={} from {}; resending cached reply",
                            request.getIdentifier(), source.getHostAddress());
                    return cached.response().clone();
                }
                log.warn("Discarding replayed Access-Request from {} (reused Request Authenticator)",
                        source.getHostAddress());
                return null;
            }

            byte[] response = authenticate(request, source);
            if (responseCache.size() >= MAX_CACHE_ENTRIES) {
                var it = responseCache.entrySet().iterator();
                it.next();
                it.remove();
            }
            responseCache.put(cacheKey, new CachedResponse(sourcePort, request.getIdentifier(), response,
                    now.plus(duplicateWindow)));
            return response.clone();
        }
    }

    private byte[] authenticate(RadiusPacket request, InetAddress source) {
        String userName = request.getUserName();
        boolean accept;
        String reason;
        if (userName == null || userName.isBlank()) {
            accept = false;
            reason = "missing User-Name";
        } else if (request.getAttribute(RadiusPacket.ATTR_EAP_MESSAGE) != null) {
            // EAP is not supported; RFC 3579 section 2.6.2 requires an Access-Reject.
            accept = false;
            reason = "EAP not supported";
        } else if (mfaPreAuthService.consumeApproval(userName)) {
            accept = true;
            reason = "MFA approval consumed";
        } else {
            accept = false;
            reason = "no active MFA approval";
        }
        log.info("RADIUS {} for user '{}' from {} ({})", accept ? "Access-Accept" : "Access-Reject",
                userName, source.getHostAddress(), reason);
        List<RadiusPacket.Attribute> attrs = accept
                ? List.of()
                : List.of(new RadiusPacket.Attribute(RadiusPacket.ATTR_REPLY_MESSAGE,
                "MFA pre-authentication required".getBytes(StandardCharsets.UTF_8)));
        return RadiusPacket.encodeResponse(accept ? RadiusPacket.ACCESS_ACCEPT : RadiusPacket.ACCESS_REJECT,
                request, attrs, sharedSecret);
    }

    private void purgeExpired(Instant now) {
        synchronized (responseCache) {
            var it = responseCache.values().iterator();
            while (it.hasNext()) {
                if (!now.isBefore(it.next().expires())) {
                    it.remove();
                } else {
                    break; // insertion-ordered with constant window => remaining entries are newer
                }
            }
        }
    }
}
