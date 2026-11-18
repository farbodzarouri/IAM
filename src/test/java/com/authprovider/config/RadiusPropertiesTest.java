package com.authprovider.config;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class RadiusPropertiesTest {

    @Test
    void defaultsMatchTransportValues() {
        RadiusProperties properties = new RadiusProperties();
        assertTrue(properties.isEnabled());
        assertEquals(1812, properties.getPort());
        assertEquals(8, properties.getWorkerThreads());
        assertEquals(1_000, properties.getWorkerQueueCapacity());
        assertEquals(30, properties.getDuplicateCacheSeconds());
        assertEquals(100_000, properties.getMaxDuplicateCacheEntries());
        assertDoesNotThrow(properties::validate);
    }

    @Test
    void invalidTransportSettingsAreRejected() {
        RadiusProperties badPort = new RadiusProperties();
        badPort.setPort(70_000);
        assertThrows(IllegalStateException.class, badPort::validate);

        RadiusProperties badWorkers = new RadiusProperties();
        badWorkers.setWorkerThreads(0);
        assertThrows(IllegalStateException.class, badWorkers::validate);

        RadiusProperties badCache = new RadiusProperties();
        badCache.setDuplicateCacheSeconds(0);
        assertThrows(IllegalStateException.class, badCache::validate);
    }
}
