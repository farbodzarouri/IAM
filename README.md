# Identity & Access Management (IAM) Provider

A modular identity, access management, and multi-factor authentication (MFA) service built with Spring Boot and standard Java SE cryptography. The service provides local and federated identity verification, time-based one-time passwords (TOTP), RFC 6287 challenge-response (OCRA), web login with Just-In-Time (JIT) provisioning, and RADIUS integration for enterprise Remote Desktop Gateway (RDG) and VPN multi-factor authentication.

---

## Core Capabilities

- **Primary Authentication**: Local database credential verification (BCrypt hashed) and LDAP / Active Directory federation (via native JNDI).
- **Multi-Factor Authentication**:
  - Time-Based One-Time Password (TOTP, RFC 6238) with clock-drift window matching and replay rejection.
  - OATH Challenge-Response Algorithm (OCRA, RFC 6287) with constant-time verification.
  - QR Code generation (`otpauth://`) for Google Authenticator, Microsoft Authenticator, and standard RFC 6238 apps.
- **Enterprise RADIUS Server**: RFC 2865 authentication server supporting both in-band challenge-response MFA and out-of-band RD Gateway pre-authentication.
- **Security Hardening**: Protected administrative APIs, write-only credential serialization, brute-force lockout protections, bounded memory caches, and directory bind throttling to prevent Active Directory account lockouts.

---

## Authentication Flows

### 1. Unified Web & REST Login (`/v1/api/auth/login`)

The primary web login endpoint coordinates directory federation, JIT enrollment, and two-factor verification:

1. **Primary Verification**:
   - If LDAP is enabled (`ldap.enabled=true`), credentials are authenticated against the directory. If the user is not found and `ldap.fallback-to-local=true`, local database credentials are checked.
   - If LDAP is disabled, credentials are authenticated against local BCrypt hashes.
2. **MFA Enrollment (First-Time Users)**:
   - If the account has no 2FA secret enrolled, a secret is generated, persisted, and returned along with an `otpauth://` URI and Base64-encoded QR code (`Status: ENROLLMENT_REQUIRED`).
3. **MFA Verification (Subsequent Logins)**:
   - When a user submits their username, password, and OTP code, the code is validated within the drift window.
   - **Replay Defense**: Once an OTP time step is consumed, subsequent re-use of the exact same code within the 90-second window is rejected.

---

### 2. Remote Desktop Gateway / RADIUS MFA

The service acts as an MFA back-end for Windows Remote Desktop Gateway, Network Policy Server (NPS), and VPN gateways. The RADIUS server supports two concurrent operational modes:

#### Mode A: Out-of-band Web Pre-Authentication
Used when the client (e.g. Windows RD Gateway) forwards an `Access-Request` *without* `User-Password` after Active Directory validates primary credentials:

1. Before connecting, the user pre-authenticates their second factor:
   - Web interface: `GET /mfa` → submit username and OTP code.
   - REST endpoint: `POST /v1/api/mfa/preauth` with `{"username": "alice", "otp": 123456}`.
2. When approved, a single-use approval is persisted (`mfa_approvals`) for the security policy's MFA approval TTL (seeded from `radius.mfa.ttl-seconds`).
3. When NPS sends an `Access-Request`, the server consumes the active approval and returns `Access-Accept`. If unapproved or expired, it returns `Access-Reject`.

#### Mode B: In-band Challenge-Response (RFC 2865)
Used when the client submits an `Access-Request` *with* `User-Password`:

1. **Step 1 (Primary Credentials)**:
   - Client sends `Access-Request` with username and primary password.
   - Server verifies credentials against LDAP or local store. Non-enrolled users receive `Access-Reject` with `Reply-Message: MFA enrollment required`.
   - Enrolled users receive `Access-Challenge` containing an OTP prompt and a single-use cryptographic `State` attribute.
2. **Step 2 (Second Factor Verification)**:
   - Client submits a second `Access-Request` containing the OTP code as `User-Password` and echoing the `State` attribute.
   - Server validates the OTP and answers `Access-Accept` or `Access-Reject`.

---

## Security Architecture & Audit Remediations

- **Access Control & Information Exposure**:
  - Administrative endpoints (`/users/**`, `/v1/api/users/**`) and secret generation (`/v1/api/otp/generate/**`) require authentication (HTTP Basic or form login).
  - Public endpoints are strictly limited to `/login`, `/mfa`, `/v1/api/auth/**`, `/v1/api/mfa/**`, and OTP verification.
  - User entity JSON serialization marks `password` and `secret` as `@JsonProperty(access = WRITE_ONLY)`, preventing credential leakage in API responses.
- **Credential Storage**:
  - Local database passwords are automatically hashed with BCrypt (`$2a$`) upon creation and update.
- **Directory Bind Throttling (Anti-Lockout)**:
  - In-band RADIUS directory lookups perform domain stripping and execute at most a single user authentication bind per packet. This avoids looping across multiple candidate identities and prevents triggering enterprise Active Directory account lockout policies.
- **Multi-Factor Replay Defense**:
  - Both web login and RADIUS MFA record and invalidate consumed TOTP time-step windows to prevent token reuse during replay attacks.
- **Denial of Service & Memory Bounds**:
  - The persistent MFA pre-authentication failure tracking is bounded to 10,000 active records with automatic eviction of expired entries.
  - Accepted TOTP time-step records are pruned past the clock-drift window.
- **Identity Collision**:
  - The user database schema enforces unique constraints on usernames with case-insensitive collision detection during provisioning.
- **Cryptographic Timing**:
  - OCRA challenge-response validation utilizes constant-time byte comparisons (`MessageDigest.isEqual`) to eliminate micro-timing side-channels.

---

## Configuration Reference

### RADIUS Properties

| Property | Default | Description |
|---|---|---|
| `radius.enabled` | `true` | Enables the RADIUS UDP authentication server |
| `radius.port` | `1812` | UDP port (`0` selects an ephemeral port for testing) |
| `radius.bind-address` | `0.0.0.0` | Network interface IP to bind |
| `radius.shared-secret` | `secret` | Shared secret between NAS/NPS and RADIUS server |
| `radius.allowed-clients` | *(empty = any)* | Comma-separated list of permitted NAS/NPS client IPs |
| `radius.mfa.ttl-seconds` | `60` | Lifetime of an out-of-band MFA approval token |
| `radius.challenge.ttl-seconds` | `60` | Lifetime of an in-band Access-Challenge `State` attribute |
| `radius.challenge.max-pending` | `10000` | Maximum pending challenge sessions permitted in memory |
| `radius.require-message-authenticator` | `false` | Discards Access-Requests lacking an RFC 3579 Message-Authenticator |
| `radius.lockout-seconds` | `300` | User lockout duration after consecutive failures |
| `radius.max-failures` | `5` | Maximum failed attempts allowed before temporary lockout |

### LDAP Directory Properties

| Property | Default | Description |
|---|---|---|
| `ldap.enabled` | `false` | Enables inbound LDAP / Active Directory federation |
| `ldap.url` | `ldap://localhost:389` | LDAP server connection URL (`ldap://` or `ldaps://`) |
| `ldap.base-dn` | `dc=example,dc=org` | Base Distinguished Name for user search |
| `ldap.user-search-filter` | `(&(objectClass=person)(|(uid={0})(sAMAccountName={0})))` | Filter for locating user entries |
| `ldap.bind-dn` | *(empty = anonymous)* | Manager DN used for user search bind |
| `ldap.bind-password` | *(empty)* | Password for manager bind DN |
| `ldap.auto-provision` | `true` | Automatically provisions local user record on first successful directory login |
| `ldap.fallback-to-local` | `false` | Fall back to local DB credentials if user is absent from directory |
| `ldap.connect-timeout-ms` | `5000` | Socket connection timeout |
| `ldap.read-timeout-ms` | `10000` | Socket read timeout |
| `ldap.realm` | *(empty)* | Realm identifier(s), comma separated, routing qualified names to the seeded directory |
| `ldap.priority` | `100` | Evaluation order of the seeded directory (lower first) |

> The `radius.*` and `ldap.*` properties above are only used to **seed** the database on first start
> (see below). Once the tables are populated, the persisted records are authoritative.

---

## Persistent Runtime Configuration & State (Clustering / Multi-Tenancy)

All runtime configuration, session tracking, security policy and audit data is stored in the database through
typed JPA entities, so several nodes can share one database and state survives restarts.

| Entity | Table | Purpose |
|---|---|---|
| `RadiusClient` | `radius_clients` | NAS / NPS clients: name, IPv4/IPv6 address **or CIDR subnet**, dedicated shared secret, `active` flag. The most specific active match for the sender address supplies the secret used to validate the Message-Authenticator, decrypt `User-Password` and sign responses. Packets from unmatched addresses are dropped. |
| `LdapDirectory` | `ldap_directories` | Federated directories: realm identifier(s), URL, base DN, search filter / DN pattern, bind credentials, timeouts, `priority`, `enabled`, `auto_provision`, `fallback_to_local`. `REALM\user` / `user@realm` is routed directly to the matching directory; unqualified names are evaluated across enabled directories in priority order (stopping at the first directory that knows the user; an unavailable directory fails closed). |
| `SecurityPolicy` | `security_policies` | Policy `default`: RADIUS lockout threshold / duration / failure window, challenge TTL and max pending sessions, MFA approval TTL, MFA pre-auth lockout threshold / window, OTP reuse window. Read on every use, so changes apply cluster-wide immediately. |
| `RadiusChallengeSession` | `radius_challenge_sessions` | Pending in-band `Access-Challenge` `State` sessions (single-use, atomically consumed). |
| `MfaApproval` | `mfa_approvals` | Out-of-band MFA pre-authentication approvals (single-use, atomically consumed). |
| `AuthFailureRecord` | `auth_failure_records` | Brute-force failure counters and lockouts (scopes `RADIUS` per user id, `MFA_PREAUTH` per user name). |
| `AuthAuditLog` | `auth_audit_logs` | Append-only log of every authentication attempt (web login, MFA pre-auth, RADIUS): time, channel, user, client address / name, outcome and failure reason. |

**Bootstrap.** When the application starts against an uninitialized database, each empty table is seeded from
the legacy properties: the `default` security policy from `radius.max-failures`, `radius.lockout-seconds`,
`radius.challenge.*` and `radius.mfa.ttl-seconds`; one RADIUS client per `radius.allowed-clients` entry (or the
catch-all clients `0.0.0.0/0` and `::/0` when empty) with `radius.shared-secret`; and one LDAP directory named
`default` from `ldap.*`. Tables that already contain data are never modified. Disable with
`iam.bootstrap.seed-defaults=false`.

---

## REST API Summary

| Method | Endpoint | Access | Description |
|---|---|---|---|
| `POST` | `/v1/api/auth/login` | Public | Primary authentication with directory routing, JIT provisioning, and MFA verification |
| `POST` | `/v1/api/mfa/preauth` | Public | Out-of-band MFA pre-authentication for RD Gateway |
| `POST` | `/v1/api/otp/validate` | Public | Validates a standard 6-digit TOTP code |
| `POST` | `/v1/api/otp/validate-ocra` | Public | Validates an OCRA challenge-response code |
| `POST` | `/v1/api/otp/generate/{id}` | Authenticated | Generates a new TOTP secret for the specified user ID |
| `GET` | `/v1/api/users/all` | Authenticated | Lists all registered user accounts (secrets & passwords excluded) |
| `GET` | `/v1/api/users/{id}` | Authenticated | Retrieves user details by ID |
| `POST` | `/v1/api/users/create` | Authenticated | Registers a new local user (passwords auto-hashed with BCrypt) |
| `PUT` | `/v1/api/users/{id}` | Authenticated | Updates existing user account details |
| `DELETE`| `/v1/api/users/{id}` | Authenticated | Deletes a user account |

---

## Building and Running

### Prerequisites
- Java 17 or higher (Java 21 supported)
- Maven 3.8+

### Build and Run Tests
```bash
mvn clean test
```

### Launch Application
```bash
mvn spring-boot:run
```
Service runs on port `8081` (configurable via `server.port`). Web UI is accessible at `http://localhost:8081/`.
