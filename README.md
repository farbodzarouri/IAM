# local authentication provider

-this is a service for generating and authenticating otp on your local machine or an addition to your system.<br/>
-consists on two services, one for creating otp and the other for validating the otp.<br/>
-supports ocra and simple otp generation and authentication.<br/>
-you are able to use its internal user management system or connect it to your own source for user management.<br/>
-it can be used for keeping track of your users and their token or it can get all data from you and do the validation phase for you. <br/>

## Remote Desktop Gateway MFA (RADIUS)

The service embeds a RADIUS server (RFC 2865 / RFC 3579, JDK only) supporting both **In-Band Two-Step Challenge/Response** and **Out-of-Band Web/REST Pre-Authentication** for Windows Remote Desktop Gateway (NPS):

### 1. In-Band Challenge/Response Mode (PAP + OTP)
1. NPS forwards an `Access-Request` (PAP) with `User-Name` and the user's primary password in `User-Password`. The password is verified against the user database. On success an `Access-Challenge` (Code 11) is returned carrying an opaque, single-use 256-bit `State`, a `Reply-Message` prompt, and `Session-Timeout`.
2. The client answers with a second `Access-Request` containing the same `User-Name`, the `State`, and the 6-digit TOTP code in `User-Password`. A valid code yields `Access-Accept` (Code 2); any invalid, expired, or replayed token yields `Access-Reject` (Code 3).

### 2. Out-of-Band Pre-Authentication Mode
1. Before connecting, the user pre-authenticates with their OTP (no login required):
   - Web form: `GET /mfa`, `POST /mfa` (form fields `username`, `otp`)
   - REST: `POST /v1/api/mfa/preauth` with `{"username": "jdoe", "otp": 123456}` → `true` / `false`
2. When NPS forwards an `Access-Request` carrying `User-Name` (without `User-Password`), the server replies `Access-Accept` only if the user holds an active, unconsumed approval, which is consumed atomically.

### Configuration Properties

| Property | Default | Description |
|---|---|---|
| `radius.port` | `1812` | UDP port (`0` = ephemeral) |
| `radius.shared-secret` | `secret` | Shared secret configured on NPS (change in production) |
| `radius.mfa.ttl-seconds` | `60` | Lifetime of an out-of-band MFA pre-auth approval |
| `radius.challenge.ttl-seconds` | `60` | Lifetime of an in-band OTP challenge (`State`) |
| `radius.enabled` | `true` | Enable/disable the RADIUS listener |
| `radius.bind-address` | `0.0.0.0` | Local address to bind |
| `radius.allowed-clients` | *(any)* | Comma-separated NAS/NPS addresses allowed to send requests |
| `radius.require-message-authenticator` | `false` | Drop requests lacking `Message-Authenticator` |
| `radius.strip-realm` | `true` | Also match `DOMAIN\user` and `user@domain` as `user` (case-insensitive) |
| `radius.max-failures` / `radius.lockout-seconds` | `5` / `300` | Per-user failure lockout policy |
| `radius.duplicate-cache-seconds` | `30` | Retransmission deduplication window |
| `radius.challenge.max-pending` | `10000` | Maximum outstanding challenges |
| `radius.challenge.prompt` | `Enter your one-time passcode` | Challenge `Reply-Message` |
