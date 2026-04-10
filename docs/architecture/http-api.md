# HTTP API

## Router Structure

**File**: `hierarkey-server/src/http_server.rs`

All authenticated endpoints live under `/v1/`. The auth endpoints (`/v1/auth/`) are exempt from the auth middleware so login and token exchange can proceed without a token.

```
/about                     GET  (public) server information
/healthz                   GET  health check (always 200)
/readyz                    GET  readiness check (migrations, master keys, admin account)

/v1/auth/login             POST
/v1/auth/refresh           POST
/v1/auth/service-account/token   POST
/v1/auth/mfa/verify        POST
/v1/auth/federated         GET  list configured federated providers
/v1/auth/federated/{provider_id} POST  exchange credential for a token
/v1/auth/whoami            GET

/v1/accounts               POST
/v1/accounts/search        POST
/v1/accounts/{account}     GET, PATCH, DELETE
/v1/accounts/{account}/promote          POST
/v1/accounts/{account}/demote           POST
/v1/accounts/{account}/lock             POST
/v1/accounts/{account}/unlock           POST
/v1/accounts/{account}/disable          POST
/v1/accounts/{account}/enable           POST
/v1/accounts/{account}/cert             POST
/v1/accounts/{account}/federated-identity  GET, POST, DELETE
/v1/accounts/{account}/password         POST (change-password purpose token required)

/v1/namespaces             POST
/v1/namespaces/search      GET
/v1/namespaces/id/{id}     GET  (lookup by short ID)
/v1/namespaces/{ns}        GET, PATCH, DELETE
/v1/namespaces/{ns}/disable      POST
/v1/namespaces/{ns}/enable       POST
/v1/namespaces/{ns}/rotate-kek   POST
/v1/namespaces/{ns}/rewrap-deks  POST

/v1/secrets                POST
/v1/secrets/search         POST
/v1/secrets/reveal         POST
/v1/secrets/{sec_ref}      GET, PATCH, DELETE
/v1/secrets/{sec_ref}/annotate  PATCH
/v1/secrets/{sec_ref}/activate  POST
/v1/secrets/{sec_ref}/revise    POST
/v1/secrets/{sec_ref}/enable    POST
/v1/secrets/{sec_ref}/disable   POST
/v1/secrets/{sec_id}/restore    POST

/v1/masterkeys             POST, GET (status)
/v1/masterkeys/{name}      GET, DELETE
/v1/masterkeys/{name}/lock        POST
/v1/masterkeys/{name}/unlock      POST
/v1/masterkeys/{name}/activate    POST
/v1/masterkeys/{name}/rewrap-keks POST

/v1/pat                    POST, GET
/v1/pat/{id}               DELETE

/v1/rbac/rule              POST
/v1/rbac/rule/search       POST
/v1/rbac/rule/{id}         GET, DELETE
/v1/rbac/role              POST
/v1/rbac/role/search       POST
/v1/rbac/role/{name}       GET, PATCH
/v1/rbac/role/{name}/rules POST
/v1/rbac/bind              POST
/v1/rbac/unbind            POST
/v1/rbac/bindings          POST
/v1/rbac/bindings/all      POST
/v1/rbac/explain           POST

/v1/system/about           GET
/v1/system/status          GET

/v1/audit/events           POST
/v1/audit/verify           POST
```

---

## AppState

**File**: `hierarkey-server/src/http_server.rs`

Shared state injected into every handler via Axum's `State` extractor.

```rust
pub struct AppState {
    pub masterkey_service:          Arc<MasterKeyService>,
    pub secret_service:             Arc<SecretService>,
    pub auth_service:               Arc<AuthService>,
    pub account_service:            Arc<AccountService>,
    pub namespace_service:          Arc<NamespaceService>,
    pub kek_service:                Arc<KekService>,
    pub token_service:              Arc<TokenService>,
    pub rbac_service:               Arc<RbacService>,
    pub license_service:            Arc<LicenseService>,
    pub audit_service:              Arc<AuditService>,
    pub system_account_id:          Option<AccountId>,
    pub pool:                       PgPool,
    pub task_manager:               Arc<BackgroundTaskManager>,
    pub sa_nonce_cache:             Arc<NonceCache>,
    pub federated_providers:        Vec<Arc<dyn FederatedAuthProvider>>,
    pub federated_identity_manager: Arc<FederatedIdentityManager>,
    pub config:                     Config,
}
```

Services are wrapped in `Arc` so cloning `AppState` per request is cheap — only reference counts are incremented.

---

## Middleware

**File**: `hierarkey-server/src/http_server/middleware/`

Middleware layers are applied in the order listed below (last registered = first executed in Axum):

1. **`audit_ctx_middleware`** — runs first. Generates a `RequestId` and `TraceId`, extracts client IP and `Origin` header, and stores an `AuditContext` in request extensions.

2. **`logging_middleware`** — logs the incoming request (method, path, user agent) and the outgoing response (status code, duration). Sanitises sensitive values to prevent log injection.

3. **`auth_middleware`** — extracts the `Authorization: Bearer <token>` header, authenticates via `AuthService`, and stores an `AuthUser` in request extensions. Returns `401` if authentication fails.

4. **`require_auth_purpose`** — applied to most `/v1/` routes. Verifies that the token's `purpose` is `Auth` (rejects Refresh or ChangePwd tokens).

5. **`require_change_password_purpose`** — applied to `PATCH /accounts/{id}/password`. Only accepts `ChangePwd` tokens.

---

## Request Extractors

**File**: `hierarkey-server/src/http_server/extractors.rs` + `auth_user.rs`

- **`AuthUser`**: Populated by `auth_middleware`. Contains `user.id`, `user.short_id`, `user.name`, and `token.purpose`.
- **`ApiJson<T>`**: A wrapper around Axum's `Json<T>` that returns structured `HttpError` responses on deserialisation failure instead of plain text.
- **`AuditContext`**: Extracted from request extensions; provides `request_id`, `trace_id`, `client_ip`.

---

## Error Handling

**File**: `hierarkey-server/src/http_server/api_error.rs`

All errors are returned as JSON:

```json
{
  "code": "ResourceNotFound",
  "reason": "NotFound",
  "message": "namespace '/org/prod' does not exist",
  "details": null
}
```

`HttpError` maps `CkError` variants to HTTP status codes:

| CkError variant | HTTP status |
|-----------------|-------------|
| `ResourceNotFound` | 404 |
| `ResourceExists` | 409 |
| `PermissionDenied` | 403 |
| `Auth(InvalidCredentials)` | 401 |
| `Validation(_)` | 422 |
| `RevisionMismatch` | 409 |
| `Database(_)` | 500 |
| everything else | 500 |

---

## Body and Timeout Limits

Configured in `hierarkey-server/src/global/mod.rs`:

| Limit | Value |
|-------|-------|
| Max request body | 5 MiB |
| Request body timeout | 30 s |
| Response body timeout | 30 s |
| Global request timeout | 30 s |
| Concurrency limit | 1000 concurrent requests |
