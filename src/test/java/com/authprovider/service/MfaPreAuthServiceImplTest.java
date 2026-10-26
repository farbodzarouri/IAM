package com.authprovider.service;

import com.authprovider.entity.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.OptionalLong;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class MfaPreAuthServiceImplTest {

    private final AtomicReference<Instant> now = new AtomicReference<>(Instant.parse("2024-01-01T00:00:00Z"));
    private final Clock clock = new Clock() {
        public ZoneOffset getZone() { return ZoneOffset.UTC; }
        public Clock withZone(java.time.ZoneId zone) { return this; }
        public Instant instant() { return now.get(); }
    };
    private UserService userService;
    private TotpService totpService;
    private MfaPreAuthServiceImpl service;

    @BeforeEach
    void setUp() {
        userService = mock(UserService.class);
        totpService = mock(TotpService.class);
        User user = User.builder().id(1L).username("JDoe").secret("S").build();
        when(userService.findByUsernameIgnoreCase(anyString())).thenReturn(List.of());
        when(userService.findByUsernameIgnoreCase("jdoe")).thenReturn(List.of(user));
        when(userService.findByUsernameIgnoreCase("JDoe")).thenReturn(List.of(user));
        when(totpService.findMatchingTimeStep(eq("S"), anyInt())).thenReturn(OptionalLong.empty());
        service = new MfaPreAuthServiceImpl(userService, totpService, clock, 60);
    }

    private void validCode(int otp, long step) {
        when(totpService.findMatchingTimeStep("S", otp)).thenReturn(OptionalLong.of(step));
    }

    @Test
    void approvalIsSingleUseAndExpires() {
        validCode(111111, 10);
        assertTrue(service.preAuthenticate("CORP\\jdoe", 111111));
        assertTrue(service.hasActiveApproval("jdoe@corp.local"));
        assertTrue(service.consumeApproval("JDOE"));
        assertFalse(service.consumeApproval("jdoe"));

        validCode(222222, 11);
        assertTrue(service.preAuthenticate("jdoe", 222222));
        now.set(now.get().plus(Duration.ofSeconds(60)));
        assertFalse(service.consumeApproval("jdoe"));
    }

    @Test
    void sameOrOlderTimeStepIsRejected() {
        validCode(111111, 10);
        validCode(333333, 9);
        assertTrue(service.preAuthenticate("jdoe", 111111));
        assertFalse(service.preAuthenticate("jdoe", 111111));
        assertFalse(service.preAuthenticate("jdoe", 333333));
    }

    @Test
    void lockoutAfterRepeatedFailures() {
        for (int i = 0; i < MfaPreAuthServiceImpl.MAX_FAILED_ATTEMPTS; i++) {
            assertFalse(service.preAuthenticate("jdoe", 1));
        }
        validCode(111111, 10);
        assertFalse(service.preAuthenticate("jdoe", 111111));
        now.set(now.get().plus(MfaPreAuthServiceImpl.LOCKOUT_WINDOW));
        assertTrue(service.preAuthenticate("jdoe", 111111));
    }

    @Test
    void invalidInput() {
        assertFalse(service.preAuthenticate(null, 1));
        assertFalse(service.preAuthenticate("  ", 1));
        assertFalse(service.preAuthenticate("jdoe", null));
        assertFalse(service.preAuthenticate("unknown", 1));
        assertFalse(service.consumeApproval(null));
        assertThrows(IllegalArgumentException.class, () -> new MfaPreAuthServiceImpl(userService, totpService, clock, 0));
    }
}
