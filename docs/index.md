# Hierarkey — Secret Management Platform

Hierarkey is a secure, hierarchical secret management platform built in Rust. It stores sensitive
secrets and keys, encrypted at rest, and makes them available only to authorized users and
applications.

---

## What is Hierarkey?

Hierarkey is an alternative to tools like HashiCorp Vault, designed to be simple to operate while
remaining cryptographically strong. It exposes an HTTP API and ships with a CLI (`hkey`) that
lets you manage secrets, namespaces, users, and access policies.

**Common use cases:**

- Storing API keys, database credentials, certificates, and other sensitive configuration
- Rotating secrets without redeploying applications
- Giving CI/CD pipelines scoped, time-limited access to only the secrets they need
- Auditing who accessed what, and when

---

## Key Features

| Feature | Description |
|---|---|
| **Encryption at rest** | Four-tier key hierarchy: Master Key -> KEK -> DEK -> Secret |
| **Namespaces** | Hierarchical grouping; each namespace has its own encryption key |
| **Secret revisions** | Every update creates a new revision - roll back at any time |
| **Secret types** | Optional type metadata (`password`, `certificate`, `json`, etc.) for filtering |
| **RBAC** | Fine-grained, pattern-based access control with roles, rules, and bindings |
| **Personal Access Tokens** | Short-lived tokens for human and script access |
| **Service accounts** | Machine accounts with Ed25519 key-signature authentication |
| **Brute-force lockout** | Failed login attempts counted; accounts locked after repeated failures |
| **Short IDs** | Every resource has a stable short ID (e.g. `ns_abc123`) usable everywhere |
| **Audit logging** | Every action logged with principal, resource, and timestamp |
| **Master key rewrap/rekey** | Rotate master key material without exposing plaintext secrets |
| **Master key providers** | File (insecure/passphrase) or HSM via PKCS#11 |
| **TLS** | Native TLS support; HTTP mode only for development |

---

## How It Works

At its core, Hierarkey keeps your secrets behind a layered encryption scheme:

```text
Master Key
  └── KEK (per namespace)
        └── DEK (per secret version)
              └── Encrypted secret value
```

The **Master Key** is the root of trust - it never touches the database. It lives in a key file,
is protected by a passphrase, or is managed by an HSM. It is used exclusively to wrap and unwrap
**KEKs** (Key Encryption Keys), one per namespace. Each secret version gets its own randomly
generated **DEK** (Data Encryption Key), wrapped by the namespace KEK, and the secret itself is
encrypted with that DEK using AES-256-GCM.

This means:

- A compromised database reveals nothing - all data is encrypted.
- A compromised DEK exposes only one secret version.
- A compromised KEK exposes only one namespace.
- The Master Key is never stored in the database.

---

## Quick Start

See the [tutorial](tutorial/hierarkey_part1_server_setup.md) for a full walkthrough. The short version:

```bash
# 1. Generate a config file and edit it (database URL, TLS, master key provider)
hierarkey generate-config --output hierarkey-config.toml

# 2. Run database migrations
hierarkey update-migrations --config hierarkey-config.toml --yes

# 3. Bootstrap the first master key
hierarkey bootstrap-master-key --config hierarkey-config.toml --usage wrap_kek --provider passphrase --generate-passphrase

# 4. Bootstrap the first admin account (generates and prints a random password)
hierarkey bootstrap-admin-account --config hierarkey-config.toml --name admin

# 5. Start the server
hierarkey serve --config hierarkey-config.toml
```

Then log in with the `hkey` CLI — note the first login returns a change-password token; see the tutorial for the full flow:

```bash
export HKEY_SERVER_URL="https://localhost:8443"
hkey auth login --name admin
export HKEY_ACCESS_TOKEN="hkat_..."

hkey namespace create --namespace /prod
hkey secret create --ref /prod:app/db-password --value "s3cr3t"
hkey secret reveal  --ref /prod:app/db-password
```

---

## Documentation Layout

- **[Getting Started](hierarkey-nutshell.md)** - What Hierarkey is and why it works this way
- **[Architecture](tutorial/hierarkey_architecture.md)** - Internals, key hierarchy, request flows, security model
- **[Tutorial](tutorial/hierarkey_part1_server_setup.md)** - Hands-on walkthrough across eight parts
- **[RBAC](rbac.md)** - Rule syntax, permissions, target kinds, and policy examples
- **[RBAC path matching](rbac-matches.md)** - How namespace and secret path patterns are evaluated
- **[TLS configuration](tls.md)** - Server TLS setup guides
- **[PostgreSQL TLS](postgres-tls.md)** - Database TLS and certificate setup

---

## Requirements

- **Rust 1.88+** (to build from source)
- **PostgreSQL 15+**
- A place to store the master key (file, passphrase-protected file, or PKCS#11 HSM)
