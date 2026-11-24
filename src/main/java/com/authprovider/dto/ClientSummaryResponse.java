package com.authprovider.dto;

import com.authprovider.entity.AuthMode;
import com.authprovider.entity.ClientType;
import com.authprovider.entity.OAuthClient;
import com.authprovider.entity.RadiusClient;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Type-independent view of a RADIUS or OAuth 2.0 client (no secrets).
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ClientSummaryResponse {
    private Long id;
    private ClientType type;
    private String name;
    private boolean enabled;
    private AuthMode authMode;

    public static ClientSummaryResponse from(RadiusClient client) {
        return ClientSummaryResponse.builder()
                .id(client.getId())
                .type(ClientType.RADIUS)
                .name(client.getName())
                .enabled(client.isActive())
                .authMode(client.getAuthMode())
                .build();
    }

    public static ClientSummaryResponse from(OAuthClient client) {
        return ClientSummaryResponse.builder()
                .id(client.getId())
                .type(ClientType.OAUTH2)
                .name(client.getName())
                .enabled(client.isEnabled())
                .authMode(client.getAuthMode())
                .build();
    }
}
