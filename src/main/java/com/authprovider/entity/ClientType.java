package com.authprovider.entity;

/**
 * Kind of a connected client a user can be assigned to.
 */
public enum ClientType {
    /** RADIUS client (NAS / NPS proxy / VPN gateway), see {@link RadiusClient}. */
    RADIUS,
    /** OAuth 2.0 machine-to-machine client, see {@link OAuthClient}. */
    OAUTH2
}
