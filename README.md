# local authentication provider

-this is a service for generating and authenticating otp on your local machine or an addition to your system.<br/>
-consists on two services, one for creating otp and the other for validating the otp.<br/>
-supports ocra and simple otp generation and authentication.<br/>
-you are able to use its internal user management system or connect it to your own source for user management.<br/>
-it can be used for keeping track of your users and their token or it can get all data from you and do the validation phase for you. <br/>

## Remote Desktop Gateway MFA (RADIUS)

The service can act as the MFA back-end for Windows Remote Desktop Gateway with NPS in RADIUS-proxy mode.

1. Before connecting, the user pre-authenticates with their OTP (no login required):
   - Web form: `GET /mfa`, `POST /mfa` (form fields `username`, `otp`)
   - REST: `POST /v1/api/mfa/preauth` with `{"username": "jdoe", "otp": 123456}` → `true` / `false`
2. After AD validates the primary credentials, NPS forwards an Access-Request over UDP. The server replies
   Access-Accept only if the user has an active, unconsumed approval, which is then consumed (single use).

Security behaviour:
- Access-Requests must include a valid Message-Authenticator (RFC 3579); other packets are silently discarded.
- Replies carry a Response Authenticator and Message-Authenticator, and echo Proxy-State attributes.
- Retransmissions get the cached reply (they never consume a second approval). Replayed Request Authenticators are dropped.
- An OTP time step can only be used once per user. Repeated failures lock the user out of pre-auth for 15 minutes.
- User names are matched case-insensitively, and `DOMAIN\user` / `user@realm` forms are normalised.

| Property | Default | Description |
|---|---|---|
| `radius.port` | `1812` | UDP port (`0` = ephemeral) |
| `radius.shared-secret` | `secret` | Shared secret configured on NPS (change it!) |
| `radius.mfa.ttl-seconds` | `60` | Lifetime of an MFA approval |
| `radius.bind-address` | `0.0.0.0` | Interface to bind |
| `radius.allowed-clients` | *(empty = any)* | Comma-separated NPS IPs allowed to send requests |
