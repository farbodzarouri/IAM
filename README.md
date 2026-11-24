# Identity & Access Management (IAM) Provider

A modular identity, access management, and multi-factor authentication (MFA) service built with Spring Boot 3.2 (Java 21) and standard Java SE cryptography. The platform models natural identities (`Person`), hardware/software second-factor tokens (`OtpToken`), separated regular vs. administrative principals (`User` and `Admin`), local BCrypt and federated LDAP / Active Directory authentication, time-based OTP (`RFC 6238` TOTP), challenge-response (`RFC 6287` OCRA), an embedded `RFC 2865` / `RFC 3579` RADIUS server for VPN and Remote Desktop Gateway (RDG) authentication, and an OAuth 2.0 machine-to-machine authorization server (`RFC 6749` client credentials, `RFC 9068` RS256 JWT access tokens) protecting the connected-system APIs.

---

## Core Capabilities

- **Natural Identity & Privilege Separation**:
  - `Person` represents a human identity owning one or more `OtpToken` generators, acting as a single enable/disable kill-switch across all linked accounts.
  - Regular `User` accounts and privileged `Admin` accounts stay strictly isolated — same-person User/Admin pairs cannot reuse primary usernames or passwords (`CredentialConflictChecker`), and directory routing separates `userEnabled` vs. `adminEnabled` LDAP directories.
  - Multiple accounts owned by the same `Person` can share an `OtpToken` with token-scoped single-use replay protection.
- **Primary Authentication & Password Service**:
  - Centralized `PasswordService` handles BCrypt hashing (`$2a$`) in the service layer, supports `{bcrypt}` / `{noop}` forms for legacy fixtures, and equalizes response timing for unknown or locked accounts using dummy BCrypt verification.
  - Federated LDAP / Active Directory authentication (`FederatedDirectoryAuthenticator` / `JndiLdapDirectoryAuthenticator`) with realm-based routing (`REALM\user`, `user@realm`), priority ordering, and per-directory Just-In-Time (JIT) provisioning or local fallback.
- **Multi-Factor Authentication & Configurable Auth Modes**:
  - Four configurable `AuthMode`s (`PASSWORD_AND_OTP`, `PASSWORD_AND_OTP_INLINE`, `PASSWORD_ONLY`, `OTP_ONLY`) resolved across `SecurityPolicy`, per-client `RadiusClient`, and per-account `User` overrides (without downgrading strict `PASSWORD_AND_OTP` accounts; `Admin` accounts always require two-factor verification).
  - RFC 6238 TOTP with clock-drift window matching, RFC 6287 OCRA constant-time challenge-response, and `otpauth://` QR provisioning (`OtpProvisioningSupport`).
- **Embedded Enterprise RADIUS Server**:
  - RFC 2865 / RFC 3579 UDP authentication server (`RadiusServer`, `RadiusAuthenticationHandler`) supporting Out-of-Band RDG pre-authentication, In-Band `Access-Challenge` (`State`), Inline `<password><6-digit-otp>`, `OTP_ONLY`, `PASSWORD_ONLY`, and `Status-Server` health checks.
- **OAuth 2.0 Machine-to-Machine Client Authentication**:
  - Connected systems authenticate with scoped `Authorization: Bearer` access tokens (RFC 6750) before calling `/v1/api/auth/login`, `/v1/api/otp/validate`, `/v1/api/otp/validate-ocra`, and `/v1/api/mfa/preauth`.
  - `client_credentials` token endpoint, RFC 7662 introspection, RFC 7009 revocation, and a public RFC 7517 JWK Set, implemented with standard Java SE cryptography only.
- **Day-0 Setup & Database-Managed Runtime Configuration**:
  - Interactive first-run `/setup` wizard and `/v1/api/setup/**` endpoints active only before initial `Admin` creation or Admin LDAP setup, locking permanently once completed.
  - All security policies, NAS/NPS clients, LDAP directories, lockouts, OTP replay state, and append-only audit records are stored in the database for cluster-safe operation.

---

## Identity Model & Authentication Flows

### 1. Day-0 First-Run `/setup` Flow
When the database has no `Admin` accounts and no enabled Admin `LdapDirectory`:
- Browser requests to `/login` automatically redirect to `/setup`, and `GET /v1/api/setup/status` returns `{"setupRequired": true}`.
- Administrators bootstrap the instance by either:
  - Creating the initial local admin (`POST /setup/admin` or `POST /v1/api/setup/admin`), or
  - Registering an Admin LDAP directory (`POST /setup/ldap` or `POST /v1/api/setup/ldap`).
- As soon as setup completes, `/setup` redirects to `/login` and `/v1/api/setup/**` permanently reject further requests with HTTP `403`.

### 2. Unified User Login (`POST /v1/api/auth/login`)
`LoginServiceImpl` only authenticates accounts holding an **enabled assignment to the calling OAuth 2.0 client** (see [User to client assignments](#user-to-client-assignments)) and evaluates authentication using the effective `AuthMode` (assignment `authMode` -> client `authMode` -> `SecurityPolicy.defaultAuthMode`):
1. **Primary Verification**:
   - In `OTP_ONLY` mode (without a password), authenticates directly against the user's enrolled TOTP secret.
   - In `PASSWORD_AND_OTP_INLINE` mode, splits the trailing 6 digits of `password` into primary password + TOTP when a separate `otp` field is omitted.
   - If LDAP is enabled (`ldap_directories` with `enabled=true` and `userEnabled=true`), routes qualified names by realm or evaluates directories in priority order, with configurable JIT provisioning (`autoProvision`; a provisioned account is assigned to the calling OAuth 2.0 client only) or fallback to local BCrypt hashes (`fallbackToLocal`).
2. **MFA Enrollment (`ENROLLMENT_REQUIRED`)**:
   - Unenrolled password accounts (except `PASSWORD_ONLY`) automatically receive a new Base32 secret, `otpauth://` URI, and Base64 PNG QR code while invalidating stale pending sessions.
3. **MFA Verification (`AUTHENTICATED` / `OTP_REQUIRED`)**:
   - Validates TOTP within the drift window via `OtpVerificationService` and rejects replayed or out-of-order time steps.

### 3. Admin Login & Two-Step Web UI (`/login`, `POST /v1/api/admin/auth/login`)
- Administrators always authenticate under strict two-factor `PASSWORD_AND_OTP` rules via `AdminLoginServiceImpl` against local BCrypt hashes or `adminEnabled` LDAP directories (`IamAdminUserDetailsService` backs Spring Security).
- Browser login (`AdminWebAuthController`) uses CSRF-protected two-step verification with session ID rotation:
  1. `POST /login` verifies primary credentials and stores a short-lived (120s) pending state without creating an authenticated session.
  2. Unenrolled admins confirm their generated TOTP secret on `/login/enroll`; enrolled admins submit TOTP on `/login/otp` before receiving `ROLE_ADMIN` session access.

### 4. Username-Based OTP & OCRA Validation (`/v1/api/otp/*`)
- Bearer protected validation endpoints (`POST /v1/api/otp/validate`, `POST /v1/api/otp/validate-ocra`) only validate accounts assigned (enabled) to the calling OAuth 2.0 client, resolve accounts by presented `username` (including realm stripping when configured) rather than internal database IDs, returning structured `OtpValidationResponse` statuses (`VALID`, `INVALID_OTP`, `LOCKED`, `NOT_ENROLLED`, `INVALID_REQUEST`) and writing `OTP_VALIDATION` audit records.
- Secret generation/rotation (`POST /v1/api/otp/generate` and `POST /v1/api/otp/generate/{username}`) requires authentication and immediately invalidates pending MFA approvals and RADIUS challenges.

### 5. Remote Desktop Gateway / RADIUS MFA
The RADIUS server listens on UDP (`radius.port`, default `1812`) and authorizes packets using the most specific matching active CIDR entry in `radius_clients`:
- **Out-of-Band Pre-Authentication** (when `Access-Request` omits `User-Password` and `mfaOutOfBandEnabled=true`):
  - User approves 2FA via `GET`/`POST /mfa` or `POST /v1/api/mfa/preauth`.
  - RADIUS atomically consumes the single-use `MfaApproval` and returns `Access-Accept` (or `Access-Reject` if absent/expired/locked).
- **In-Band Challenge-Response** (`PASSWORD_AND_OTP`, RFC 2865):
  - Step 1 validates primary credentials and returns `Access-Challenge` with a cryptographic `State` token and `Reply-Message` prompt; Step 2 consumes `State` (bound to user and client IP) and validates TOTP.
- **Inline MFA (`PASSWORD_AND_OTP_INLINE`)**, **`PASSWORD_ONLY`**, and **`OTP_ONLY`**:
  - Applied per user assignment `authMode`, `RadiusClient.authMode` or `SecurityPolicy.defaultAuthMode` (in that order).
- **Client assignment**: every request is refused unless the user holds an enabled assignment to the requesting RADIUS client (also re-checked when answering an `Access-Challenge` and before consuming an out-of-band MFA approval).
- **Diagnostics**: `Status-Server` (code `12`) with a valid RFC 3579 `Message-Authenticator` returns `Access-Accept`.

### 6. OAuth 2.0 Machine-to-Machine Clients (`/oauth2/*`, `/v1/api/oauth-clients`)
Connected systems are registered as confidential OAuth 2.0 clients in the `clients` table (`/v1/api/oauth-clients`, `ROLE_ADMIN` only). Each client has a `clientId`, BCrypt-hashed `clientSecret`, `name`, `enabled`, `blocked`, an optional `authMode` override, and `scopes`:

| Scope | Grants access to |
|---|---|
| `auth:login` | `POST /v1/api/auth/login` |
| `otp:validate` | `POST /v1/api/otp/validate`, `POST /v1/api/otp/validate-ocra` |
| `mfa:preauth` | `POST /v1/api/mfa/preauth` |

1. **Token request (RFC 6749 section 4.4)**: `POST /oauth2/token` with HTTP Basic client authentication (`client_secret_basic`, form-urlencoded `client_id:client_secret`) and form body `grant_type=client_credentials[&scope=...]`. An omitted `scope` defaults to the client's registered scopes; requesting unregistered or unknown scopes fails with `invalid_scope`. Parameters in the query string, repeated parameters, `client_secret` in the body and non-form content types are rejected. Responses carry `Cache-Control: no-store`; no refresh tokens are issued.
   ```bash
   curl -u "$CLIENT_ID:$CLIENT_SECRET" -d grant_type=client_credentials -d scope=otp:validate \
        http://localhost:8081/oauth2/token
   ```
2. **Access tokens (RFC 9068 / RFC 7519 / RFC 7515)**: RS256 JWS compact serialization with header `{"typ":"at+jwt","alg":"RS256","kid":<RFC 7638 thumbprint>}` and claims `iss`, `sub` (= `client_id`), `aud`, `exp`, `iat`, `nbf`, `jti`, `client_id`, `scope`, and `ver` (client credential/permission version).
3. **Calling protected endpoints (RFC 6750)**: `Authorization: Bearer <access_token>` only (tokens in query/form parameters are rejected). Missing tokens return `401` with `WWW-Authenticate: Bearer realm="iam"`; invalid, expired or revoked tokens `401 error="invalid_token"`; missing scopes `403 error="insufficient_scope"`. Verification accepts only `RS256` with a key from this server's own key store (`none`, symmetric algorithms, `crit`, `jku`/`jwk`/`x5u`/`x5c` headers are rejected) and validates `typ`, `iss`, `aud`, `exp`/`iat`/`nbf` (with `iam.oauth2.clock-skew-seconds`).
4. **Introspection (RFC 7662)**: `POST /oauth2/introspect` (HTTP Basic, `token=...`) returns `{"active":true, scope, client_id, token_type, exp, iat, nbf, sub, aud, iss, jti}` for the caller's own valid tokens and `{"active":false}` otherwise.
5. **Revocation (RFC 7009)**: `POST /oauth2/revoke` (HTTP Basic, `token=...[&token_type_hint=access_token]`) records the token `jti` in `oauth_revoked_tokens`; invalid or expired tokens are answered with `200`, tokens of another client with `400 unauthorized_client`.
6. **JWK Set (RFC 7517 / RFC 7518)**: `GET /oauth2/jwks` (public, `application/jwk-set+json`) publishes the RSA public keys (`kty`, `use=sig`, `alg=RS256`, `kid`, `n`, `e`).
7. **Per-client `AuthMode`**: `/v1/api/auth/login` resolves the user's assignment `authMode` -> calling client's `authMode` -> `SecurityPolicy.defaultAuthMode`, exactly like RADIUS (a strict `PASSWORD_AND_OTP` assignment may submit its OTP inline for a `PASSWORD_AND_OTP_INLINE` client).

**Client registry API** (`/v1/api/oauth-clients/all`, `/{id}`, `/create`, `PUT /{id}`, `DELETE /{id}`, `POST /{id}/rotate-secret`): `clientId` and `clientSecret` are generated when omitted on create; the plain secret is returned only in the create/rotation response. `PUT` is partial (omitted fields are preserved, explicit `"authMode": null` removes the override); a non-empty `clientSecret` rotates the secret. `blocked` reports persistent administrative blocks while `locked` and `lockedUntil` report active brute-force lockouts; setting `"blocked": false` unblocks the client and clears active lockouts.

### User to client assignments
A user can only authenticate, validate an OTP / OCRA response or pre-authenticate MFA through a RADIUS or OAuth 2.0 client it holds an **enabled assignment** for; unassigned requests are refused with the generic failure response before any credential is checked (and without counting towards lockouts). Each assignment stores the client's database id (`clientId`), `enabled` (default `true`) and a nullable `authMode` that overrides the client's mode. Assignments are managed by administrators via `PUT /v1/api/users/{userId}/radius-clients/{clientId}` (body `{"enabled": true, "authMode": null}`, both optional; `PUT` replaces the assignment) and the matching `GET` / `DELETE` endpoints (likewise for `oauth-clients`), or as `radiusClients` / `oauthClients` lists in the `/v1/api/users` payloads (a list replaces the corresponding assignments). Deleting a user or client removes its assignments. Accounts auto-provisioned from LDAP during `/v1/api/auth/login` are assigned to the calling OAuth 2.0 client only.

---

## Security Architecture

- **Master Kill-Switch (`Person.enabled`)**: Disabling a `Person` immediately invalidates pending RADIUS challenges and MFA approvals and blocks all linked `User` and `Admin` logins across every channel.
- **Factor-Aware Lockout (`AccountLockoutService`)**:
  - Attempts are reserved *before* second-factor verification (`tryBeginAttempt`) so concurrent requests across nodes cannot exceed `maxFailures`.
  - **1st-factor / unauthenticated `User` failures** (wrong password, malformed inline suffix, `OTP_ONLY`, direct `/v1/api/otp/validate`, unapproved out-of-band RADIUS, MFA pre-auth) lock only the `User` account (`RADIUS` / `MFA_PREAUTH` scopes) without DoS-locking a linked `Admin` sharing the same physical token.
  - **Post-password 2nd-factor OTP failures** and **`Admin` failures** lock the `OtpToken` (`OTP_TOKEN` scope) as well as the account (`ADMIN` / `RADIUS` scopes), blocking shared-token access across both roles.
- **Single-Use Token & User Replay Defense (`OtpVerificationService`)**:
  - When an `OtpToken` is bound, TOTP time steps (`TOKEN:<id>`) and OCRA challenges are tracked against the token itself so an OTP consumed by a `User` cannot be replayed by an `Admin` (or vice versa) across web, REST, MFA pre-auth, or RADIUS.
- **OAuth 2.0 Client Security**:
  - **Brute force**: client secret verification on `/oauth2/token`, `/oauth2/introspect` and `/oauth2/revoke` uses the `SecurityPolicy` thresholds (`maxFailures`, `failureWindowSeconds`, `lockoutSeconds`) through the cluster-wide `AccountLockoutService` (`OAUTH_CLIENT` scope) with attempt reservation before the BCrypt comparison; unknown, disabled, blocked and locked clients incur equal BCrypt work and receive the same `invalid_client` response.
  - **Immediate invalidation**: every bearer use and introspection re-checks the shared database: the `jti` revocation list, client existence, `enabled`, `blocked`, the token's scopes against the client's current scopes, and the `ver` claim. Rotating the secret, changing `clientId` or scopes, disabling, blocking or deleting a client regenerates its token version so previously issued tokens stop working on all nodes at once (re-enabling never revives them).
  - **Cluster-safe keys**: RSA signing keys (`iam.oauth2.signing-key-size`, default 2048 bits) are stored in `oauth_signing_keys` and shared by all nodes, rotated every `iam.oauth2.signing-key-rotation-seconds` with the successor key pre-published in the JWK Set, and retired only after the tokens they signed have expired. Private keys are AES-256-GCM encrypted at rest when `iam.oauth2.key-encryption-secret` is set (strongly recommended).
  - Bearer authentication is stateless (no HTTP session) and only applies to the four protected endpoints; bearer tokens never grant access to admin APIs, and admin sessions cannot call the protected endpoints without a token.
- **Immutable Audit Trail (`AuthAuditLog`)**:
  - Marked `@Immutable` with `@PreUpdate`/`@PreRemove` guards rejecting modification or deletion; logs `WEB_LOGIN`, `ADMIN_LOGIN`, `MFA_PREAUTH`, `OTP_VALIDATION`, `RADIUS`, `OAUTH2_TOKEN`, `OAUTH2_INTROSPECTION`, `OAUTH2_REVOCATION`, `OAUTH2_BEARER` (rejected bearer tokens), and `OAUTH2_CLIENT_ADMIN` (client registry changes, with the acting admin) events across `SUCCESS`, `FAILURE`, `LOCKED`, `CHALLENGE`, `ENROLLMENT_REQUIRED`, and `ERROR` outcomes. Events of the protected REST endpoints record the calling OAuth 2.0 `client_id` (`clientName`) and remote address.
- **Consistent REST API Errors (`GlobalExceptionHandler`)**:
  - Maps `BadRequestException` (`400`), `SetupAlreadyCompletedException` (`403`), `ResourceNotFoundException` (`404`), `ConflictException` (`409`), and validation errors to RFC 7807 `ProblemDetail` payloads with an `"error"` property.
- **Access Control & DTOs (`SecurityConfig`, `UserResponse`, `AdminResponse`, `OpenApiConfig`)**:
  - Connected-system endpoints require scoped bearer tokens, `/v1/api/clients/**`, `/v1/api/oauth-clients/**`, `/v1/api/users/{userId}/radius-clients|oauth-clients/**`, `/v3/api-docs/**` and `/swagger-ui/**` require `ROLE_ADMIN`, and other endpoints outside public auth/setup paths require authentication (HTTP `401` on `/v1/api/**` and `/v3/api-docs/**`, redirect to `/login` for browser routes).
  - API controllers bind `UserRequest` / `AdminRequest` DTOs (never JPA entities) and return `UserResponse` / `AdminResponse` excluding passwords and secrets; partial `PUT` updates preserve existing `enabled` status when omitted.

---

## Configuration Reference

Runtime policies, NAS clients, and LDAP directories live in the database. Application properties configure UDP transport, worker sizing, and optional Day-0 seeding when tables are empty.

### RADIUS Transport Properties (`radius.*`)

| Property | Default | Description |
|---|---|---|
| `radius.enabled` | `true` | Enables the embedded RADIUS UDP server |
| `radius.port` | `1812` | UDP port (`0` selects an ephemeral port) |
| `radius.bind-address` | *(wildcard)* | Network interface IP to bind (blank binds `0.0.0.0`) |
| `radius.worker-threads` | `8` | Worker thread pool size for packet handling |
| `radius.worker-queue-capacity` | `1000` | Bounded queue capacity before packets are dropped |
| `radius.duplicate-cache-seconds` | `30` | Retransmission cache TTL for identical UDP packets |
| `radius.max-duplicate-cache-entries` | `100000` | Maximum cached duplicate request entries |

### OAuth 2.0 Properties (`iam.oauth2.*`)
Must be identical on every cluster node. Clients, signing keys and revocations live in the database.

| Property | Default | Description |
|---|---|---|
| `iam.oauth2.issuer` | `urn:authprovider:iam` | `iss` claim of issued access tokens |
| `iam.oauth2.audience` | `urn:authprovider:iam:api` | `aud` claim required on access tokens |
| `iam.oauth2.access-token-ttl-seconds` | `300` | Access token lifetime (`expires_in`, 1-86400) |
| `iam.oauth2.clock-skew-seconds` | `30` | Tolerated node clock difference for `exp`/`iat`/`nbf` |
| `iam.oauth2.signing-key-size` | `2048` | RSA modulus size of generated signing keys (2048-8192) |
| `iam.oauth2.signing-key-rotation-seconds` | `2592000` (30 days) | Signing key rotation interval |
| `iam.oauth2.key-cache-seconds` | `30` | Per-node signing key cache lifetime (unknown `kid`s trigger a reload) |
| `iam.oauth2.key-encryption-secret` | *(empty)* | Encrypts private signing keys at rest; supply via environment / secret store |

### Optional First-Boot Seeding (`iam.bootstrap.*`)
Applied only when `iam.bootstrap.seed-defaults=true` (default) and the target table is empty:

| Property | Default | Description |
|---|---|---|
| `iam.bootstrap.seed-defaults` | `true` | Enables initial DB seeding on empty tables |
| `iam.bootstrap.admin.enabled` | `true` | Allows seeding initial `Admin` if credentials are set |
| `iam.bootstrap.admin.username` | *(empty)* | Initial admin username (otherwise use `/setup`) |
| `iam.bootstrap.admin.password` | *(empty)* | Initial admin password (BCrypt-hashed via `AdminService`) |
| `iam.bootstrap.admin.display-name` | *(username)* | `Person.displayName` for seeded bootstrap admin |
| `iam.bootstrap.radius.shared-secret` | *(empty)* | Seeds `default` (`0.0.0.0/0`) / `default-ipv6` (`::/0`) or listed clients if supplied |
| `iam.bootstrap.radius.allowed-clients` | *(empty)* | Optional IPs, CIDRs, or hostnames seeded instead of catch-all entries |
| `iam.bootstrap.policy.max-failures` | `5` | Overrides seeded `default` `SecurityPolicy.maxFailures` |
| `iam.bootstrap.policy.lockout-seconds` | `300` | Overrides seeded `lockoutSeconds` and `failureWindowSeconds` |
| `iam.bootstrap.policy.challenge-ttl-seconds` | `60` | Overrides seeded `challengeTtlSeconds` |
| `iam.bootstrap.policy.mfa-approval-ttl-seconds` | `60` | Overrides seeded `mfaApprovalTtlSeconds` |

### Optional First-Boot LDAP Seed (`ldap.*`)
Seeded as the `default` `LdapDirectory` only when `ldap_directories` is empty and `ldap.enabled=true` or `ldap.url` is set:

| Property | Default | Description |
|---|---|---|
| `ldap.enabled` | `false` | Enables inbound LDAP / Active Directory federation |
| `ldap.url` | *(empty)* | LDAP connection URL (`ldap://` or `ldaps://`) |
| `ldap.base-dn` | *(empty)* | Base Distinguished Name for directory searches |
| `ldap.user-search-filter` | `(&(objectClass=person)(|(uid={0})(sAMAccountName={0})))` | Search filter locating user entries |
| `ldap.user-dn-pattern` | *(empty)* | Direct bind DN pattern (skips search bind when set) |
| `ldap.bind-dn` | *(empty)* | Service account DN for directory search bind |
| `ldap.bind-password` | *(empty)* | Service account password |
| `ldap.realm` | *(empty)* | Comma-separated realm alias(es) routed to this directory |
| `ldap.priority` | `100` | Evaluation priority (ascending) |
| `ldap.auto-provision` | `true` | Enables JIT local account provisioning |
| `ldap.fallback-to-local` | `false` | Falls back to local BCrypt password if user is absent |
| `ldap.connect-timeout-ms` | `5000` | Socket connection timeout |
| `ldap.read-timeout-ms` | `10000` | Socket read timeout |
| `ldap.referral` | `ignore` | JNDI referral handling policy |
| `ldap.username-attributes` | `uid,sAMAccountName` | Ordered attributes for canonical username extraction |

---

## Persistent Entities & State

| Entity | Table | Purpose |
|---|---|---|
| `Person` | `persons` | Natural identity (`firstName`, `lastName`, `displayName`, unique `email`, `mobile`, `nationalCode`) owning `OtpToken`s and linked accounts (`enabled` master switch) |
| `OtpToken` | `otp_tokens` | Single source of truth for hardware/app TOTP & OCRA secrets |
| `User` | `users` | End-user login principal, local BCrypt password, `Person`/`OtpToken` links (no OTP secret of its own) |
| `UserRadiusClient` | `user_radius_clients` | Assignment of a user to a RADIUS client: `clientId`, `enabled` (default `true`), optional `authMode` override |
| `UserOAuthClient` | `user_oauth_clients` | Assignment of a user to an OAuth 2.0 client: `clientId`, `enabled` (default `true`), optional `authMode` override |
| `Admin` | `admins` | Privileged admin principal linked to `Person` and `OtpToken` with strict 2FA |
| `RadiusClient` | `radius_clients` | NAS/NPS clients: CIDR/IP match, shared secret, active flag, optional `AuthMode` |
| `LdapDirectory` | `ldap_directories` | Federated LDAP configs with `userEnabled`/`adminEnabled` separation, realms, and priority |
| `SecurityPolicy` | `security_policies` | Cluster-wide `default` policy (lockout, TTLs, `stripRealm`, `defaultAuthMode`, `mfaOutOfBandEnabled`) |
| `RadiusChallengeSession` | `radius_challenge_sessions` | Single-use in-band `Access-Challenge` `State` sessions bound to user and client IP |
| `MfaApproval` | `mfa_approvals` | Single-use out-of-band MFA pre-authentication approvals |
| `AuthFailureRecord` | `auth_failure_records` | Optimistically locked brute-force counters (`RADIUS`, `MFA_PREAUTH`, `ADMIN`, `OTP_TOKEN`, `OAUTH_CLIENT`) |
| `OtpReplayState` | `otp_replay_state` | Atomic monotonic TOTP time-step tracking per `TOKEN:<id>` or `USER:<id>` |
| `OcraChallengeUse` | `ocra_challenge_uses` | Single-use hashed OCRA challenge replay tracking per `TOKEN:<id>` or `USER:<id>` |
| `AuthAuditLog` | `auth_audit_logs` | Append-only (`@Immutable`) authentication audit log |
| `OAuthClient` | `clients` | OAuth 2.0 M2M clients: `clientId`, BCrypt secret hash, `enabled`, `blocked`, optional `AuthMode`, scopes, token version |
| `OAuthSigningKey` | `oauth_signing_keys` | Cluster-shared RS256 key pairs with signing / verification validity periods |
| `OAuthRevokedToken` | `oauth_revoked_tokens` | RFC 7009 revoked access token `jti`s (purged after expiry) |

---

## REST & Web Endpoints Summary

| Method | Endpoint | Access | Description |
|---|---|---|---|
| `GET` / `POST` | `/setup`, `/setup/admin`, `/setup/ldap` | Public (Day-0 only) | First-run browser setup wizard (locks once complete) |
| `GET` | `/v1/api/setup/status` | Public | Returns whether initial setup is still required |
| `POST` | `/v1/api/setup/admin` | Public (Day-0 only) | Creates initial local `Admin` + `Person` (locks setup) |
| `POST` | `/v1/api/setup/ldap` | Public (Day-0 only) | Registers initial Admin `LdapDirectory` (locks setup) |
| `POST` | `/oauth2/token` | HTTP Basic client | `client_credentials` grant issuing RS256 JWT access tokens |
| `POST` | `/oauth2/introspect` | HTTP Basic client | RFC 7662 token introspection |
| `POST` | `/oauth2/revoke` | HTTP Basic client | RFC 7009 access token revocation |
| `GET` | `/oauth2/jwks` | Public | RFC 7517 JWK Set of token signing keys |
| `POST` | `/v1/api/auth/login` | Bearer `auth:login` | End-user REST authentication across configured `AuthMode`s |
| `POST` | `/v1/api/admin/auth/login` | Public | Admin REST login (primary + strict 2FA / enrollment) |
| `GET` / `POST` | `/login`, `/login/otp`, `/login/enroll` | Public | CSRF-protected 2-step browser admin login & TOTP enrollment |
| `GET` / `POST` | `/mfa` | Public | Browser MFA pre-authentication page for RDG |
| `POST` | `/v1/api/mfa/preauth` | Bearer `mfa:preauth` | Out-of-band MFA pre-authentication API |
| `POST` | `/v1/api/otp/validate` | Bearer `otp:validate` | Validates 6-digit TOTP by `username` |
| `POST` | `/v1/api/otp/validate-ocra` | Bearer `otp:validate` | Validates OCRA challenge-response by `username` |
| `POST` | `/v1/api/otp/generate` | Authenticated | Rotates/provisions TOTP secret by JSON `{"username": ...}` |
| `POST` | `/v1/api/otp/generate/{username}` | Authenticated | Rotates/provisions TOTP secret for `username` |
| `GET` / `POST` / `PUT` / `DELETE` | `/v1/api/persons/**`, `/{id}/tokens`, `/tokens/{tokenId}/rotate` | Authenticated | Manages `Person` profiles and `OtpToken` lifecycle/rotation |
| `POST` | `/v1/api/registration`, `/v1/api/users/register` | `ROLE_ADMIN` | Atomically creates/links `Person`, optional `OtpToken`, `User`, and client assignments |
| `GET/POST/PUT/DELETE` | `/v1/api/users/all`, `/{id}`, `/create` | Authenticated | Manages end-user accounts (`UserRequest` / `UserResponse`, including `radiusClients` / `oauthClients` assignments) |
| `GET/POST/PUT/DELETE` | `/v1/api/admins/all`, `/{id}`, `/create` | Authenticated | Manages admin accounts (`AdminRequest` / `AdminResponse`) |
| `GET/POST/PUT/DELETE` | `/v1/api/radius-clients/all`, `/{id}`, `/create` | Authenticated | Manages allowed RADIUS clients and per-client secrets/modes |
| `GET/POST/PUT/DELETE` | `/v1/api/ldap-directories/all`, `/{id}`, `/create` | Authenticated | Manages federated LDAP directories |
| `GET/POST/PUT/DELETE` | `/v1/api/oauth-clients/all`, `/{id}`, `/create`, `/{id}/rotate-secret` | `ROLE_ADMIN` | Manages OAuth 2.0 M2M clients, scopes, secrets, blocks and auth modes |
| `GET` | `/v1/api/clients/all[?type=RADIUS\|OAUTH2]` | `ROLE_ADMIN` | Lists all clients across types (`id`, `type`, `name`, `enabled`, `authMode`; no secrets) |
| `GET` / `GET` / `PUT` / `DELETE` | `/v1/api/users/{userId}/radius-clients`, `/{clientId}` | `ROLE_ADMIN` | Lists, reads, creates/replaces and removes a user's RADIUS client assignments |
| `GET` / `GET` / `PUT` / `DELETE` | `/v1/api/users/{userId}/oauth-clients`, `/{clientId}` | `ROLE_ADMIN` | Lists, reads, creates/replaces and removes a user's OAuth 2.0 client assignments |
| `GET` / `PUT` | `/v1/api/policies/current` | Authenticated | Reads or updates the cluster-wide `default` `SecurityPolicy` |
| `GET` / `POST` | `/users/**`, `/logout` | Authenticated | Thymeleaf admin user management & OTP QR views |
| `GET` | `/v3/api-docs`, `/swagger-ui.html` | `ROLE_ADMIN` | OpenAPI v3 specification and Swagger UI for `/v1/api/**` and `/oauth2/**` |

---

## Building and Running

### Prerequisites
- **Java 21** (Eclipse Adoptium JDK 21 or compatible)
- **Maven 3.9+**

### Build and Run Tests
```bash
mvn clean test
```

### Launch Application
```bash
mvn spring-boot:run
```
> **Upgrading existing databases**: the new `clients`, `oauth_signing_keys` and `oauth_revoked_tokens` tables are created by schema generation. If `auth_audit_logs.channel` was created with an enum `CHECK` constraint, extend it with the `OAUTH2_*` channels (or drop it) before upgrading.

Service listens on HTTP port `8081` (`server.port`) and UDP RADIUS port `1812` (`radius.port`). Open `http://localhost:8081/` to launch first-run `/setup` or `/login`.
