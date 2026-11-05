# local authentication provider

-this is a service for generating and authenticating otp on your local machine or an addition to your system.<br/>
-consists on two services, one for creating otp and the other for validating the otp.<br/>
-supports ocra and simple otp generation and authentication.<br/>
-you are able to use its internal user management system or connect it to your own source for user management.<br/>
-it can be used for keeping track of your users and their token or it can get all data from you and do the validation phase for you. <br/>

## Remote Desktop Gateway MFA (RADIUS)

The service can act as the MFA back-end for Windows Remote Desktop Gateway / NPS. The RADIUS server supports two
modes concurrently; the mode is selected per Access-Request:

**Out-of-band web pre-authentication** (Access-Request *without* `User-Password`)

1. Before connecting, the user pre-authenticates with their OTP (no login required):
   - Web form: `GET /mfa`, `POST /mfa` (form fields `username`, `otp`)
   - REST: `POST /v1/api/mfa/preauth` with `{"username": "jdoe", "otp": 123456}` → `true` / `false`
2. After AD validates the primary credentials, NPS forwards an Access-Request over UDP. The server replies
   Access-Accept only if the user has an active, unconsumed approval, which is then consumed (single use).

**In-band challenge-response** (RFC 2865 Access-Challenge, Access-Request *with* `User-Password`)

1. Access-Request with user name and password: primary credentials are verified and the user must already be
   enrolled in two-factor authentication. The server answers Access-Challenge with a single-use `State`.
2. Access-Request with the OTP as `User-Password` and the `State` echoed: Access-Accept / Access-Reject.

Security behaviour:
- A present but invalid Message-Authenticator (RFC 3579) causes the packet to be silently discarded;
  `radius.require-message-authenticator=true` makes it mandatory. EAP and CHAP are rejected.
- Replies carry a Response Authenticator and Message-Authenticator, and echo Proxy-State attributes.
- Retransmissions get the cached reply (they never consume a second approval or challenge). Replayed Request Authenticators are dropped.
- An OTP can only be used once per user. Repeated failures lock the user out.
- User names are matched case-insensitively, and `DOMAIN\user` / `user@realm` forms are normalised.

| Property | Default | Description |
|---|---|---|
| `radius.enabled` | `true` | Start the RADIUS server |
| `radius.port` | `1812` | UDP port (`0` = ephemeral) |
| `radius.shared-secret` | `secret` | Shared secret configured on NPS (change it!) |
| `radius.mfa.ttl-seconds` | `60` | Lifetime of an out-of-band MFA approval |
| `radius.mfa.out-of-band-enabled` | `true` | Accept Access-Requests without `User-Password` by consuming an approval |
| `radius.challenge.ttl-seconds` | `60` | Lifetime of an in-band Access-Challenge `State` |
| `radius.require-message-authenticator` | `false` | Discard Access-Requests without Message-Authenticator |
| `radius.bind-address` | `0.0.0.0` | Interface to bind |
| `radius.allowed-clients` | *(empty = any)* | Comma-separated NPS IPs allowed to send requests |

### LDAP directory users over RADIUS

When `ldap.enabled=true`, in-band RADIUS primary credentials are verified against the directory (JNDI, no extra
dependencies) instead of local passwords:

- The directory identity is linked to the local account with the same (canonical) user name. The account must
  already be enrolled in two-factor authentication (e.g. via `POST /v1/api/auth/login`); RADIUS never provisions
  accounts or issues enrollment secrets, so non-enrolled directory users receive Access-Reject.
- An invalid directory password is always rejected; local passwords are only used for users unknown to the
  directory and only when `ldap.fallback-to-local=true`.
- `DOMAIN\user` / `user@realm` names are reduced to the account name before the directory lookup
  (`radius.strip-realm=true`).
