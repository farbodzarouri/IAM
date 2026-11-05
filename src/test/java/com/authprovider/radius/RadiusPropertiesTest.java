package com.authprovider.radius;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class RadiusPropertiesTest {

    @Test
    void defaultsMatchDocumentedValues() {
        RadiusProperties properties = new RadiusProperties();
        assertEquals(1812, properties.getPort());
        assertEquals("secret", properties.getSharedSecret());
        assertEquals(60, properties.getChallenge().getTtlSeconds());
        assertDoesNotThrow(properties::validate);
    }

    @Test
    void invalidSettingsAreRejected() {
        RadiusProperties emptySecret = new RadiusProperties();
        emptySecret.setSharedSecret("");
        assertThrows(IllegalStateException.class, emptySecret::validate);

        RadiusProperties badTtl = new RadiusProperties();
        badTtl.getChallenge().setTtlSeconds(0);
        assertThrows(IllegalStateException.class, badTtl::validate);

        RadiusProperties badPort = new RadiusProperties();
        badPort.setPort(70000);
        assertThrows(IllegalStateException.class, badPort::validate);
    }
}
