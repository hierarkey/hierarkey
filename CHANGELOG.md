# Changelog

## [Unreleased]

## [0.4.0] - 2026-04-10

### Added
- Federated authentication for service accounts: OIDC JWT and Kubernetes ServiceAccount Token exchange. Service accounts can be linked to a federated identity via `hkey account link-federated-identity`, and at runtime exchange a provider-issued credential for a short-lived Hierarkey token (Commercial Edition). Community edition supports configuring providers and linking identities.
- `hkey auth list-providers`: list the federated authentication providers configured on the server (no authentication required)
- `hkey rbac bindings --all`: admin flag to list RBAC bindings across all accounts (previously only the current user's bindings were available without directly querying the API)
- RBAC-scoped search: secret and namespace search results are now filtered to only include resources the caller has permission to see
- `created_by` and `updated_by` fields are now tracked and displayed for namespaces, master keys, RBAC roles, and RBAC rules
- License expiry grace period: a Commercial license within 30 days of expiry now shows a warning rather than immediately reverting to Community tier

### Fixed
- Improved CLI error message when the Hierarkey server is unreachable or offline

### Security
- Documented why RUSTSEC-2023-0071 (Marvin Attack, `rsa` crate) does not affect this project: the RSA algorithms in the OIDC provider are used exclusively for JWT signature *verification* (public-key operations); the vulnerable private-key path is never exercised
- Updated `deny.toml` advisory ignore entry to reflect both dependency paths (`sqlx-mysql` and `jsonwebtoken`) that bring in the `rsa` crate

### Documentation
- Comprehensive review and rewrite of all `docs/architecture/` files: corrected permission names in RBAC reference, completed HTTP route table, rewrote CLI reference with accurate flags, added federated authentication section to authentication docs
- Fixed all CLI command examples in guides (`docs/guides/`) to use correct flag names, required arguments, and env var names
- Added RBAC patterns guide
- Added `CONTRIBUTING.md` and expanded `README.md`

## [0.3.0] - 2026-04-02

### Added
- Audit log system: all sensitive operations (login, secret access, account changes, PAT creation/revocation, etc.) are now recorded with actor, timestamp, and event type
- `hkey audit` CLI command: query and verify audit events
- Audit event verification: cryptographic integrity check on audit log entries
- MFA (multi-factor authentication): TOTP-based second factor support for login, including backup codes
- `hkey auth mfa-verify` CLI command and `--env` flag for non-interactive MFA flows
- Prometheus metrics endpoint: request counts, login attempts, and other operational metrics (configurable)
- CORS support: configurable allowed origins, methods, and headers
- Rate limiting: configurable per-IP request rate limits via `governor`
- Security headers middleware: configurable HTTP security headers (CSP, HSTS, X-Frame-Options, etc.)
- `hkey about` command: displays server edition, version, and build information
- Account limits removed: no longer a cap on the number of accounts in community edition

### Changed
- License changed from MIT to AGPLv3; a separate commercial license applies to the commercial edition
- Community/commercial split: mTLS client-certificate authentication is now a commercial-only feature
- License generator moved to the commercial edition
- `--ttl-minutes` flag replaced by `--ttl` accepting human-readable durations (e.g. `30m`, `2h`)

### Fixed
- Token TTL was not applied correctly when issuing short-lived tokens

## [0.2.7] - 2026-03-17

### Added
- PKCS#11 master key provider: AES-256 keys can now be stored and used via any PKCS#11-compatible HSM (SoftHSM, YubiHSM, AWS CloudHSM, etc.)
- `hkey masterkey pkcs11-tokens` CLI command: list available PKCS#11 tokens and slots
- `hkey masterkey create --provider pkcs11` and `hkey masterkey unlock` now accept PKCS#11 options (slot, token label, key label, PIN)
- SoftHSM setup and configuration guide (`docs/softhsm.md`)

## [0.2.6] - 2026-03-16

### Added
- KEK rewrapping: master keys can now rewrap KEKs onto a new master key without exposing plaintext secrets
- Master key rekey: rotate the underlying key material of a master key
- RBAC permission caching: RBAC checks are now cached to reduce database load on hot paths
- Short IDs are now accepted as lookup identifiers in all selection contexts (namespace, secret, master key, etc.)

### Changed
- Integration tests now run automatically on merges to main

### Fixed
- Prevented creation of duplicate master key names
- Config file keys are now parsed case-insensitively
- Accounts cannot edit other users' account details without admin privileges
- User-controlled `X-Forwarded-For` / IP headers are now sanitized before use
- Access token TTL is now capped at the server-configured maximum
- Requests without a resolvable client IP are rejected
- TOCTOU race condition in account creation guarded with a mutex
- Admin-or-self checks applied consistently to account search and describe endpoints

## [0.2.5] - 2026-03-08

### Added
- RBAC soft-delete: roles and rules are now soft-deleted (audit trail preserved); names can be reused after deletion
- RBAC role-rule removal is now soft (recorded with actor and timestamp); re-adding a removed rule reactivates the existing row
- Brute-force lockout: failed login attempts are now counted and accounts are temporarily locked after repeated failures
- `auth refresh` CLI command: exchange a refresh token for a new access/refresh token pair

### Changed
- CLI account commands now consistently use `--account` (was sometimes `--name`)
- RBAC delete/remove operations now record the acting account (`deleted_by` / `removed_by`)

### Fixed
- System accounts are blocked from obtaining service-account tokens via the `/v1/auth/token` endpoint
- Brute-force lockout checks (account locked / account inactive) are now also enforced on the Ed25519 key-signature token path
- Startup migration check now correctly detects pending migrations (previous implementation always reported up-to-date)

## [0.2.4] - 2026-03-04

### Added
- RBAC role bindings: `hkey rbac bind` and `hkey rbac unbind` commands
- RBAC explain: `hkey rbac explain` to show effective permissions for a subject
- RBAC bindings API: list, add, and remove role assignments per subject

### Changed
- RBAC visibility: only accounts with `rbac:admin` permission can view RBAC data for other users

### Fixed
- Parent namespace permission checks removed (permissions are now scoped to the target namespace only)

## [0.2.3] - 2026-02-22

### Added
- Service accounts: machine accounts with API key authentication (no password required)
- RBAC service: initial role and rule infrastructure with database migrations
- Signal handler: graceful shutdown via SIGTERM/SIGINT using a background task manager

### Changed
- Server binary renamed from `hierarkey-server` to `hierarkey`
- CLI `destroy` subcommand renamed to `delete` for consistency
- Environment variable renamed from `HKEY_API_TOKEN` to `HKEY_ACCESS_TOKEN`

## [0.2.2] - 2026-02-03

Internal release.

## [0.2.1] - 2026-02-02

Initial release.

### Added
- Namespace management: create, list, describe, enable, disable, delete, restore
- Secret management: create, list, describe, reveal, update, delete with full revision history
- Master key management: generate, list, describe, lock, unlock, retire, rekey, rewrap
- Personal Access Tokens: create, list, revoke
- Account management: create, list, describe, promote/demote admin, lock/unlock, delete
- Authentication: password login and PAT-based login
- Status command: server health and master key status overview
- PostgreSQL backend with full migration support
- TLS support for both the API server and database connections
- GPG-signed release checksums
