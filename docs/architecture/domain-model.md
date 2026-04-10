# Domain Model

## Entities and Relationships

```
Account
  │
  ├── PersonalAccessToken (PAT) — 1:N
  ├── RBAC Bindings — N:M via rbac_account_rules / rbac_account_roles
  └── audit actor on most mutations

Namespace
  │
  ├── KekAssignment (active) ─────> KEK ──> MasterKey
  ├── KekAssignment (history, revisions)
  └── Secret (1:N)
        └── SecretRevision (1:N, encrypted with KEK/DEK)

MasterKey
  └── KEK (1:N — one master key wraps many KEKs)

Role
  └── Rule (N:M via rbac_role_rules)

Account ──(bound to)──> Rule (direct)
Account ──(bound to)──> Role ──> Rule
```

---

## Account

**Table**: `accounts` | **ID prefix**: `acc_`

Represents a human user, a machine service account, or the built-in system actor.

| Field | Type | Notes |
|-------|------|-------|
| `id` | UUID | Internal identifier |
| `short_id` | ShortId | External identifier (e.g., `acc_abc123`) |
| `name` | AccountName | Unique login name |
| `account_type` | enum | `User`, `Service`, `System` |
| `status` | enum | `Active`, `Locked`, `Disabled`, `Deleted` |
| `password_hash` | String | Argon2id (64 MiB, 3 iterations) |
| `failed_login_attempts` | i32 | Reset on successful login |
| `must_change_password` | bool | Forces password change at next login |

**System account** (`$system`): A built-in account of type `System`. No password, cannot be deleted. Its `AccountId` is preloaded into `AppState.system_account_id` at startup and used as the actor for automated operations.

**Brute-force lockout**: After N consecutive failed logins the account is locked until `locked_until` expires. The threshold and duration are configurable.

---

## Namespace

**Table**: `namespaces` | **ID prefix**: `ns_`

A node in the resource hierarchy. Namespace paths follow a filesystem-like convention: `/org/team/env`.

| Field | Type | Notes |
|-------|------|-------|
| `id` | UUID | Internal identifier |
| `short_id` | ShortId | External identifier |
| `namespace` | NamespaceString | Unique path, e.g. `/org/prod` |
| `status` | ResourceStatus | `Active`, `Disabled`, `Deleted` |
| `metadata` | Metadata | Labels and arbitrary key/value pairs |
| `created_by` | AccountId? | Actor who created it |
| `status_changed_by` | AccountId? | Actor who last changed status |

Each namespace has exactly one **active KEK assignment** — a link to the KEK used to encrypt new secrets in that namespace. Historical assignments are kept for re-wrapping and audit purposes.

---

## Secret and SecretRevision

**Tables**: `secrets`, `secret_revisions` | **ID prefixes**: `sec_`, `rev_`

A `Secret` is the container; a `SecretRevision` holds the actual encrypted value.

### Secret

| Field | Type | Notes |
|-------|------|-------|
| `id` | UUID | Internal |
| `short_id` | ShortId | External |
| `namespace_id` | NamespaceId | Owning namespace |
| `ref_ns` | String | Namespace portion of the full ref |
| `ref_key` | String | Key portion (e.g., `app/db/password`) |
| `active_revision` | Revision | Which revision is currently canonical |
| `latest_revision` | Revision | Highest revision number issued |

Full secret reference format: `/namespace:key/path` — for example `/org/prod:app/db/password@3` (with optional revision suffix).

### SecretRevision

Each revision is independently encrypted with its own DEK.

| Field | Type | Notes |
|-------|------|-------|
| `revision` | u32 | Monotonically increasing per secret |
| `encrypted_secret` | BYTEA | AES-256-GCM ciphertext of the secret value |
| `encrypted_dek` | BYTEA | DEK encrypted with the namespace KEK |
| `kek_id` | KekId | Which KEK encrypted this revision's DEK |

---

## MasterKey

**Table**: `masterkeys` | **ID prefix**: `mk_`

The root of the encryption hierarchy. Wraps KEKs.

| Field | Type | Notes |
|-------|------|-------|
| `id` | UUID | Internal |
| `short_id` | ShortId | External |
| `backend` | enum | `File`, `Pkcs11` |
| `file_type` | enum | `Insecure` (plaintext), `Passphrase` (encrypted) |
| `status` | MasterKeyStatus | See lifecycle below |

**Status lifecycle**:

```
Pending ──(activate)──> Active ──(superseded by new Active)──> Draining
                                                                    │
                                              (all KEKs rewrapped)──> Retired
```

- `Pending`: Created, not yet active. Cannot wrap KEKs.
- `Active`: Currently used to wrap new KEKs. At most one key is Active at any time.
- `Draining`: Superseded but still decrypts existing KEKs. No new KEKs wrapped.
- `Retired`: No KEKs reference it. Not loaded at startup.
- `Unavailable`: Key material is missing (file deleted, HSM unreachable).

All loaded master keys start **locked** in the keyring. An unlock API call (providing the passphrase or HSM PIN) transitions the key to unlocked, making it available for cryptographic operations.

---

## KEK (Key Encryption Key)

**Table**: `keks` | **ID prefix**: `kek_`

A 32-byte symmetric key stored encrypted in the database. Each namespace's active KEK assignment points to one KEK.

| Field | Type | Notes |
|-------|------|-------|
| `id` | UUID | Internal |
| `short_id` | ShortId | External |
| `ciphertext` | BYTEA | KEK encrypted by its master key (AES-256-GCM) |
| `masterkey_id` | MasterkeyId | Which master key wraps this KEK |
| `rotation_count` | u32 | How many times this KEK has been rotated |

Decrypted KEKs are held in a bounded in-memory cache (`KekCache`, max 1000 entries). They are `Zeroizing<[u8; 32]>` and are zeroed when evicted or dropped.

---

## DEK (Data Encryption Key)

Not stored as a separate table row. Each `SecretRevision` carries its own DEK, encrypted with the namespace KEK at write time and stored inline in `secret_revisions.encrypted_dek`.

Format: `nonce (12 B) || encrypted_DEK (32 B) || GCM tag (16 B)` = 60 bytes.

Decrypted DEKs are `Zeroizing<[u8; 32]>` and zeroed on drop.

---

## PersonalAccessToken (PAT)

**Table**: `tokens` | **ID prefix**: `pat_`

Bearer tokens used to authenticate API requests.

| Field | Type | Notes |
|-------|------|-------|
| `id` | UUID | Embedded in the token string itself |
| `short_id` | ShortId | External |
| `account_id` | AccountId | Owner |
| `token_hash` | BYTEA | BLAKE3 hash — the raw token is never stored |
| `token_suffix` | String | Last 8 chars — shown to user for identification |
| `purpose` | TokenPurpose | `Auth`, `Refresh`, `ChangePwd` |
| `expires_at` | DateTime | Hard expiry |
| `revoked_at` | DateTime? | Soft revocation |

Token string prefixes indicate purpose:

| Prefix | Purpose |
|--------|---------|
| `hkat_` | Auth token — full API access |
| `hkrt_` | Refresh token — exchange for a new auth token |
| `hkcp_` | Change-password token — one-time use |

The raw token value is returned once at creation time and never stored. Authentication hashes the presented token with BLAKE3 and compares to `token_hash`.

---

## RBAC Entities

See [rbac.md](rbac.md) for the full permission model. The core entities are:

- **Rule** (`rbac_rules`, prefix `rul_`): A single allow/deny statement with a permission, target pattern, and optional condition.
- **Role** (`rbac_roles`, prefix `rol_`): A named collection of rules.
- **Binding**: Links an account to a rule (direct) or a role (indirect). Stored in `rbac_account_rules` and `rbac_account_roles`. All bindings support optional `valid_from` / `valid_until` windows.
