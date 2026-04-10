# Startup Sequence

**File**: `hierarkey-server/src/startup.rs` and `hierarkey-server/src/bin/main.rs`

## Sequence

```
1. Load config (hierarkey-config.toml)
2. Connect to PostgreSQL
3. Run pending migrations
4. Check system account exists
5. Load master keys into keyring (all locked)
6. Check admin account exists
7. Reload license from database
8. Build AppState
9. Start HTTP server
```

### 1. Load Config

Reads `hierarkey-config.toml` from the working directory (or a path set via `HIERARKEY_CONFIG`). Validates required fields: database URL, bind address, master key provider config.

### 2. Connect to PostgreSQL

Creates a `PgPool` from the configured `database_url`. The pool size is configurable.

### 3. Run Migrations

Applies any unapplied SQL migration files from `hierarkey-server/migrations/`. Migration files are numbered and applied in order. The server refuses to start if the schema is not up-to-date.

### 4. Check System Account

Queries the database for an account with name `$system` and type `System`.

- If missing: exits with **code 7** (`StartupError::SystemAccountMissing`).
- On success: stores the `AccountId` in `AppState.system_account_id`.

The system account must be seeded before first run using the bootstrap command.

### 5. Load Master Keys

Fetches all non-retired master keys from the `masterkeys` table. For each key:

1. Determines the provider type from `backend` + `file_type`.
2. Instantiates the appropriate provider (`PassphraseProvider`, `InsecureProvider`, `Pkcs11Provider`).
3. Registers the key in the `MasterKeyKeyring` as **locked**.

All keys start locked — no passphrase or PIN is provided at startup. Keys must be unlocked explicitly via the API.

If no master keys exist in the database: exits with **code 6**.

### 6. Check Admin Account

Queries for at least one active account with platform-admin privileges.

If none exists: exits with **code 5**.

### 7. Reload License

Calls `LicenseService::reload()`, which:

1. Reads the `platform_license` table.
2. If no row exists: prints `[  OK  ] License — Community tier (no license installed)` and sets Community as the effective tier.
3. If a row exists: verifies the Ed25519 signature and expiry.
   - Valid: prints tier, licensee, expiry; sets the effective license.
   - Expired: prints `[ WARN ]`, falls back to Community.
   - Invalid: logs a warning, falls back to Community.

### 8. Build AppState

Constructs `AppState` with all services, the database pool, and shared caches. All services are wrapped in `Arc`.

### 9. Start HTTP Server

Builds the Axum router (`build_router`) and starts listening on the configured bind address. Supports plain HTTP or TLS (rustls). Handles `SIGTERM` and `Ctrl-C` for graceful shutdown.

---

## Startup Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success (clean shutdown) |
| 1 | General error |
| 5 | No admin account found |
| 6 | No master key found |
| 7 | System account (`$system`) missing |

---

## Readiness vs Health

**`GET /healthz`** — always returns `200 OK`. Used by load balancers to confirm the process is alive.

**`GET /readyz`** — returns `200` only when the server has passed its startup checks (migrations complete, master key loaded, admin account present). Returns `503` during initialisation or if a critical check has failed.
