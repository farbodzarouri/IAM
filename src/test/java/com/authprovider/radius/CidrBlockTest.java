package com.authprovider.radius;

import com.authprovider.entity.RadiusClient;
import com.authprovider.repository.RadiusClientRepository;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class CidrBlockTest {

    @Test
    void matchesDiscreteAddressesAndSubnets() throws Exception {
        assertTrue(CidrBlock.parse("10.1.2.3").matches(InetAddress.getByName("10.1.2.3")));
        assertFalse(CidrBlock.parse("10.1.2.3").matches(InetAddress.getByName("10.1.2.4")));
        assertTrue(CidrBlock.parse("10.1.2.0/24").matches(InetAddress.getByName("10.1.2.200")));
        assertFalse(CidrBlock.parse("10.1.2.0/24").matches(InetAddress.getByName("10.1.3.1")));
        assertTrue(CidrBlock.parse("10.1.2.77/24").matches(InetAddress.getByName("10.1.2.1")));
        assertTrue(CidrBlock.parse("0.0.0.0/0").matches(InetAddress.getByName("192.168.5.5")));
        assertTrue(CidrBlock.parse("172.16.0.0/12").matches(InetAddress.getByName("172.31.255.255")));
        assertFalse(CidrBlock.parse("172.16.0.0/12").matches(InetAddress.getByName("172.32.0.0")));
        assertTrue(CidrBlock.parse("fd00::/8").matches(InetAddress.getByName("fd12::1")));
        assertFalse(CidrBlock.parse("10.0.0.0/8").matches(InetAddress.getByName("fd12::1")));
    }

    @Test
    void rejectsInvalidValuesWithoutDnsLookups() {
        for (String invalid : new String[]{"", "host.example.org", "10.0.0.256", "10.0.0.0/33", "10.0.0.0/", "1.2.3", "10.0.0.0/-1"}) {
            assertFalse(CidrBlock.isValid(invalid), invalid);
        }
        assertTrue(CidrBlock.isValid("::/0"));
        assertTrue(CidrBlock.isValid("192.168.0.1/32"));
    }

    @Test
    void registryPrefersMostSpecificActiveClient() throws Exception {
        RadiusClientRepository repository = mock(RadiusClientRepository.class);
        when(repository.findByActiveTrue()).thenReturn(List.of(
                RadiusClient.builder().id(1L).name("any").address("0.0.0.0/0").sharedSecret("any").active(true).build(),
                RadiusClient.builder().id(2L).name("lan").address("10.0.0.0/8").sharedSecret("lan").active(true).build(),
                RadiusClient.builder().id(3L).name("nps").address("10.0.0.5").sharedSecret("nps").active(true).build(),
                RadiusClient.builder().id(4L).name("broken").address("not-an-ip").sharedSecret("x").active(true).build()));
        RadiusClientRegistry registry = new RadiusClientRegistry(new RadiusProperties(), repository);

        assertEquals("nps", registry.resolve(InetAddress.getByName("10.0.0.5")).orElseThrow().name());
        assertArrayEquals("lan".getBytes(StandardCharsets.UTF_8),
                registry.resolve(InetAddress.getByName("10.9.9.9")).orElseThrow().secret());
        assertEquals("any", registry.resolve(InetAddress.getByName("8.8.8.8")).orElseThrow().name());

        when(repository.findByActiveTrue()).thenReturn(List.of(
                RadiusClient.builder().id(2L).name("lan").address("10.0.0.0/8").sharedSecret("lan").active(true).build()));
        assertTrue(registry.resolve(InetAddress.getByName("8.8.8.8")).isEmpty());
    }
}
