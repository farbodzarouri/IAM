package com.authprovider.service;

import com.authprovider.entity.AuthAuditLog;
import com.authprovider.oauth2.OAuthClientAuthentication;
import com.authprovider.repository.AuthAuditLogRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Clock;
import java.util.Optional;

/**
 * Records authentication attempts, outcomes and failure reasons in the append-only
 * {@code auth_audit_logs} table. Auditing never interferes with authentication: persistence
 * errors are logged and swallowed.
 */
@Slf4j
@Service
public class AuthAuditService {

    private static final int MAX_USERNAME_LENGTH = 256;
    private static final int MAX_FIELD_LENGTH = 128;

    private static final AuthAuditService NO_OP = new AuthAuditService(null, Clock.systemUTC());

    private final AuthAuditLogRepository repository;
    private final Clock clock;

    @Autowired
    public AuthAuditService(AuthAuditLogRepository repository, Clock clock) {
        this.repository = repository;
        this.clock = clock;
    }

    /** An audit service that discards events (for embedded / unit-test use). */
    public static AuthAuditService noOp() {
        return NO_OP;
    }

    /** Fluent event builder. */
    public Event event(AuthAuditLog.Channel channel, AuthAuditLog.Outcome outcome) {
        return new Event(channel, outcome);
    }

    public void record(AuthAuditLog.Channel channel, String username, Long userId, String clientAddress,
                       String clientName, AuthAuditLog.Outcome outcome, String reason, String source) {
        if (repository == null) {
            return;
        }
        if (clientName == null && clientAddress == null) {
            // REST calls made by a connected system: record the authenticated OAuth 2.0 client and its address.
            Optional<OAuthClientAuthentication.Client> caller = currentOAuthClient();
            if (caller.isPresent()) {
                clientName = caller.get().clientId();
                clientAddress = currentRemoteAddress();
            }
        }
        try {
            repository.save(AuthAuditLog.builder()
                    .occurredAt(clock.instant())
                    .channel(channel)
                    .username(truncate(username, MAX_USERNAME_LENGTH))
                    .userId(userId)
                    .clientAddress(truncate(clientAddress, 64))
                    .clientName(truncate(clientName, MAX_FIELD_LENGTH))
                    .outcome(outcome)
                    .reason(truncate(reason, MAX_FIELD_LENGTH))
                    .source(truncate(source, 32))
                    .build());
        } catch (RuntimeException e) {
            log.error("Failed to write authentication audit record ({} {} {})", channel, outcome, reason, e);
        }
    }

    private static Optional<OAuthClientAuthentication.Client> currentOAuthClient() {
        try {
            return OAuthClientAuthentication.current();
        } catch (RuntimeException e) {
            return Optional.empty();
        }
    }

    private static String currentRemoteAddress() {
        if (RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes) {
            return attributes.getRequest().getRemoteAddr();
        }
        return null;
    }

    private static String truncate(String value, int max) {
        if (value == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder(Math.min(value.length(), max));
        for (int i = 0; i < value.length() && sb.length() < max; i++) {
            char c = value.charAt(i);
            sb.append(Character.isISOControl(c) ? '?' : c);
        }
        return sb.toString();
    }

    public final class Event {
        private final AuthAuditLog.Channel channel;
        private final AuthAuditLog.Outcome outcome;
        private String username;
        private Long userId;
        private String clientAddress;
        private String clientName;
        private String reason;
        private String source;

        private Event(AuthAuditLog.Channel channel, AuthAuditLog.Outcome outcome) {
            this.channel = channel;
            this.outcome = outcome;
        }

        public Event username(String value) {
            this.username = value;
            return this;
        }

        public Event userId(Long value) {
            this.userId = value;
            return this;
        }

        public Event clientAddress(String value) {
            this.clientAddress = value;
            return this;
        }

        public Event clientName(String value) {
            this.clientName = value;
            return this;
        }

        public Event reason(String value) {
            this.reason = value;
            return this;
        }

        public Event source(String value) {
            this.source = value;
            return this;
        }

        public void log() {
            record(channel, username, userId, clientAddress, clientName, outcome, reason, source);
        }
    }
}
