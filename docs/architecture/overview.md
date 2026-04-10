# Overview

Hierarkey is a self-hosted secret management system. It stores secrets (API keys, passwords, certificates, connection strings) in an encrypted PostgreSQL database, organises them in a hierarchical namespace tree, and enforces fine-grained access control with a pattern-based RBAC engine.

## Design Goals

- **Encryption at rest** — secrets never touch the database in plaintext; a three-layer key hierarchy (MasterKey → KEK → DEK) separates key material from data
- **Hierarchical organisation** — namespaces mirror filesystem paths (`/org/prod`, `/team/staging`), making permission policies easy to reason about
- **Auditability** — every mutation records who did it and when; status transitions are tracked with actor and reason
- **Pluggable key backends** — passphrase-protected files, plaintext files (dev only), and PKCS#11 hardware tokens

## Crate Structure

The workspace contains three crates:

```
hierarkey/
├── hierarkey-core/       shared types, errors, domain structs
├── hierarkey-server/     HTTP server + all business logic (library + binary)
└── hierarkey-cli/        hkey CLI binary
```

### hierarkey-core

Shared types used by all other crates. Contains `CkError`, `CkResult<T>`, label and metadata types, resource identifier types (`AccountName`, `NamespaceString`, `SecretRef`, `Revision`), the license data structures, and the API status/error code enums.

### hierarkey-server

The main server. Structured in three layers:

- `manager/` — raw SQL operations (one manager per entity)
- `service/` — business logic that orchestrates one or more managers
- `http_server/` — Axum router, middleware, and handlers

Also contains the RBAC engine (`rbac.rs`), startup logic (`startup.rs`), audit context (`audit_context.rs`), and shared utilities (`global/`).

### hierarkey-cli

The `hkey` binary. A thin HTTP client built on top of `reqwest` and `clap`. Imports types directly from `hierarkey_server` for DTO definitions. Has no business logic of its own.

## Dependency Graph

```
hierarkey-cli ──────────> hierarkey-server ──────> hierarkey-core
```

## Key Technology Choices

| Concern | Choice |
|---------|--------|
| HTTP framework | Axum (tokio async) |
| Database | PostgreSQL via sqlx |
| Symmetric encryption | AES-256-GCM (aes-gcm crate) |
| Password KDF | Argon2id |
| License / SA token signing | Ed25519 (ed25519-dalek) |
| Token hashing | BLAKE3 |
| Concurrency primitives | parking_lot RwLock |
| Secrets in memory | zeroize / Zeroizing<T> |
| Config | TOML (config crate) |
