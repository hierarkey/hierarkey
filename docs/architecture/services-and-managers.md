# Services and Managers

## Layering

Business logic is split across two layers:

```
HTTP Handler
    │
    ▼
Service  (orchestration, cross-cutting logic, RBAC checks)
    │
    ▼
Manager  (SQL operations, one entity per manager)
```

Services own the business rules. Managers own the database queries. Handlers own HTTP concerns (request parsing, response serialisation, error mapping).

---

## Services

All service methods accept a `&CallContext` for audit tracking. Services are held in `AppState` behind `Arc` so they can be cloned across request handlers without copying the underlying state.

### AccountService
**File**: `hierarkey-server/src/service/account.rs`

- Account CRUD (create, update, describe, search, delete)
- Password hashing and verification (Argon2id)
- Admin grant / revoke (guards against removing the last admin and against promoting System accounts)
- Brute-force lockout reset

### AuthService
**File**: `hierarkey-server/src/service/auth.rs`

- Login: verifies password, applies lockout logic, issues auth + refresh PATs
- Token authentication: validates a presented bearer token via `TokenService`
- Timing-attack mitigation: performs a dummy hash verify even when the account doesn't exist

### TokenService
**File**: `hierarkey-server/src/service/token.rs`

- Create, revoke, restore, and describe PATs
- Token authentication: hash lookup, expiry check, revocation check
- Updates `last_used_at` on each successful authentication

### NamespaceService
**File**: `hierarkey-server/src/service/namespace.rs`

- Namespace CRUD and status transitions (disable, restore, delete)
- KEK rotation: creates a new KEK, assigns it to the namespace
- Delegates to `KekService` for all key operations

### SecretService
**File**: `hierarkey-server/src/service/secret.rs`

- Secret and revision CRUD
- Encrypts secrets on write (generates DEK, encrypts with current namespace KEK)
- Decrypts secrets on reveal (fetches KEK, decrypts DEK, decrypts secret)
- Revision activation and search

### KekService
**File**: `hierarkey-server/src/service/kek.rs`

- Generate new KEK (random bytes, wrap with active master key)
- Decrypt KEK (unwrap from DB using master key)
- Rewrap KEKs from one master key to another
- Manages the in-memory `KekCache`

### MasterKeyService
**File**: `hierarkey-server/src/service/masterkey.rs`

- Master key lifecycle: create, activate, lock, unlock, retire
- Loads key files / HSM references into the in-memory `MasterKeyKeyring`
- Delegates actual crypto to provider implementations

### RbacService
**File**: `hierarkey-server/src/service/rbac.rs`

- Rule / role / binding CRUD
- `is_allowed(account, permission, resource)` — the main permission check
- `explain(account, permission, resource)` — returns the matched rule and near-misses

### LicenseService
**File**: `hierarkey-server/src/service/license.rs`

- Verifies and parses signed license JSON (Ed25519 signature check + expiry)
- Persists the license to the `platform_license` table
- Exposes the current `EffectiveLicense` (tier, max accounts, expiry)
- Falls back to Community tier if no valid license is loaded

### AuditService
**File**: `hierarkey-server/src/service/audit.rs`

- Query audit log events with filters (actor, time range, action type)
- Verify the integrity of the audit log chain (tamper detection)

---

## Managers

Each manager has a trait (the interface) and a SQL implementation (`Sql*Store`). In-memory implementations exist for unit tests (`InMemory*Store`).

| Manager | Trait | SQL impl | In-memory impl |
|---------|-------|----------|----------------|
| AccountManager | `AccountStore` | `SqlAccountStore` | `InMemoryAccountStore` |
| NamespaceManager | `NamespaceStore` | `SqlNamespaceStore` | — |
| SecretManager | `SecretStore` | `SqlSecretStore` | — |
| KekManager | `KekStore` | `SqlKekStore` | `InMemoryKekStore` |
| MasterKeyManager | `MasterKeyStore` | `SqlMasterKeyStore` | `InMemoryMasterKeyStore` |
| TokenManager | `TokenStore` | `SqlTokenStore` | `InMemoryTokenStore` |
| RbacManager | `RbacStore` | `SqlRbacStore` | `InMemoryRbacStore` |

Managers take a `PgPool` reference and use `sqlx` for all queries. They do not contain business logic — no permission checks, no cross-entity orchestration.

---

## MasterKey Keyring

**File**: `hierarkey-server/src/service/masterkey/keyring.rs`

The keyring is an in-process registry of loaded master keys. It sits between `MasterKeyService` and the provider implementations.

```rust
struct MasterKeyKeyring {
    entries: RwLock<HashMap<MasterkeyId, KeyEntry>>,
}

struct KeyEntry {
    status: KeyStatus,
    // KeyStatus::Locked   — no crypto handle, key material not in memory
    // KeyStatus::Unlocked — holds a Box<dyn CryptoHandle> for wrap/unwrap
}
```

When the server starts, all non-retired master keys are loaded as `Locked`. An unlock API call invokes the provider, which reads the key file (or talks to the HSM) and returns a `CryptoHandle`. The handle is stored in the keyring until explicitly locked or the process exits.

---

## Background Task Manager

**File**: `hierarkey-server/src/task_manager.rs`

Manages long-running background tasks (e.g., periodic KEK rotation checks). Provides graceful shutdown: when a shutdown signal is received, it waits for running tasks to complete before the process exits.
