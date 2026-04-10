# Authentication

## Token Types

Every API request (except login and token exchange) must include an `Authorization: Bearer <token>` header. Three token types exist, distinguished by prefix:

| Prefix | Purpose | Typical TTL |
|--------|---------|-------------|
| `hkat_` | Auth — full API access | hours to days |
| `hkrt_` | Refresh — exchange for a new auth token without re-entering a password | days |
| `hkcp_` | Change-password — one-time use, only accepted on the change-password endpoint | minutes |

Tokens are stored as BLAKE3 hashes in the `tokens` table. The raw token value is returned once at creation time and never stored.

---

## Password Login

**Endpoint**: `POST /v1/auth/login`

```
Request:
  account_name: string
  password: string
  ttl_minutes: int (optional, server-capped at 7 days)

Response:
  auth_token: string     ("hkat_...")
  refresh_token: string  ("hkrt_...")
  auth_expires_at: datetime
  refresh_expires_at: datetime
  account_id: ShortId
  account_name: string
```

**Flow**:

1. Fetch account by name.
2. If account not found: perform a dummy Argon2id verify to normalise response time, then return `InvalidCredentials`.
3. Check account status: deleted, disabled, or locked accounts are rejected.
4. If still locked from a previous brute-force: check whether `locked_until` has passed.
5. Verify password with Argon2id (64 MiB memory, 3 iterations).
6. On failure: increment `failed_login_attempts`; lock account if threshold reached.
7. On success: reset `failed_login_attempts`, update `last_login_at`, generate two PATs (auth + refresh).

**Password hashing parameters** (from `hierarkey-server/src/manager/account.rs`):
- Algorithm: Argon2id
- Memory: 64 MiB
- Iterations: 3
- Parallelism: 1

---

## Token Authentication (per-request)

1. `auth_middleware` extracts `Authorization: Bearer <token>`.
2. Token format is validated (correct prefix, parseable).
3. Token is hashed with BLAKE3; the hash is looked up in `tokens` by ID.
4. Checks: token not expired, not revoked, owning account exists and is active.
5. `last_used_at` is updated.
6. `AuthUser` is stored in request extensions for handlers to use.

---

## Token Refresh

**Endpoint**: `POST /v1/auth/refresh`

Exchanges a refresh token (`hkrt_`) for a new auth token without requiring a password.

```
Request:
  Authorization: Bearer hkrt_...

Response:
  auth_token: string
  auth_expires_at: datetime
  (+ optionally a new refresh token)
```

The refresh token must have `purpose = Refresh`. Client IP is checked if it was recorded at creation time.

---

## Service Account Authentication (Ed25519)

Machine clients can authenticate using an Ed25519 key pair without a password.

**Endpoint**: `POST /v1/auth/service-account/token`

```
Request:
  account_name: string
  public_key: string   (base64 Ed25519 public key)
  nonce: string        (random value, used once)
  signature: string    (Ed25519 signature of the nonce)

Response:
  auth_token: string
  expires_at: datetime
```

**Flow**:

1. Fetch account by name; verify it is of type `Service`.
2. Check the nonce has not been used before (`NonceCache`, TTL = 120 s).
3. Verify the Ed25519 signature over the nonce using the account's registered public key.
4. Store the nonce in the cache (replay prevention).
5. Generate and return an auth token.

The `NonceCache` is a bounded in-memory cache with a 120-second TTL — twice the timestamp acceptance window, ensuring every valid nonce is tracked for at least as long as it could legitimately be replayed.

---

## Personal Access Tokens (PATs)

Users can create long-lived PATs for automation.

**Create**: `POST /v1/pat`
- `description`: human-readable label
- `ttl_minutes`: requested lifetime (server-capped at 7 days, minimum 1 minute)
- Returns raw token once — never retrievable again

**List**: `GET /v1/pat` — shows description, suffix, expiry, last-used, status

**Revoke**: `DELETE /v1/pat/{id}`

PATs are independent of session tokens and can be created and revoked without affecting other sessions.

---

## Federated Authentication

Service accounts can authenticate using an external identity provider (OIDC JWT or Kubernetes ServiceAccount token) instead of a password or private key. This allows CI/CD platforms like GitHub Actions and GitLab CI to authenticate without storing a long-lived credential.

### Configuration

Federated providers are configured in `[[auth.federated]]` blocks in the server config:

```toml
[[auth.federated]]
provider  = "oidc"
id        = "github"
issuer    = "https://token.actions.githubusercontent.com"
audience  = "https://hierarkey.example.com"

[[auth.federated]]
provider  = "k8s-tokenreview"
id        = "k8s-prod"
api_server = "https://kubernetes.default.svc"
```

### Linking an identity

A service account must be linked to a federated identity before it can use this flow:

```bash
hkey account link-federated-identity \
  --name myapp \
  --provider-id github \
  --external-issuer "https://token.actions.githubusercontent.com" \
  --external-subject "repo:myorg/myrepo:ref:refs/heads/main"
```

The `external_subject` (the `sub` claim for OIDC, or username/UID for Kubernetes) and `external_issuer` uniquely identify the caller within that provider.

### Token exchange

**Endpoint**: `GET /v1/auth/federated` — list configured providers (no auth required)

**Endpoint**: `POST /v1/auth/federated/{provider_id}` — exchange a credential for a Hierarkey token

```
Request:
  credential: string   (OIDC JWT or k8s ServiceAccount token)
  ttl_minutes: int     (optional)

Response:
  auth_token: string
  expires_at: datetime
```

**Flow**:

1. Look up the provider by `provider_id`.
2. Call `provider.exchange(credential)` — this validates the JWT signature, expiry, issuer, and audience (OIDC), or performs a Kubernetes TokenReview API call.
3. Resolve the returned `(external_issuer, external_subject)` pair against the `federated_identities` table to find the linked service account.
4. Verify the account is active.
5. Return an auth token for that service account.

### Provider types

| Type | Mechanism | Community |
|------|-----------|-----------|
| `oidc` | Validates OIDC JWT via JWKS (provider's public key) | Yes |
| `k8s-tokenreview` | Calls Kubernetes TokenReview API | Yes |

**File**: `hierarkey-server/src/http_server/federated_auth_provider.rs` (trait definition)
