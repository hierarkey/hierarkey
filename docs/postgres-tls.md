# PostgreSQL TLS Configuration

## Why TLS?

This application uses TLS (Transport Layer Security) to encrypt all communication between the application and PostgreSQL database. This ensures that:

- **Data is encrypted in transit** - Credentials, queries, and sensitive data cannot be intercepted
- **Server identity is verified** - The application confirms it's connecting to the legitimate database server
- **Man-in-the-middle attacks are prevented** - Encrypted communication prevents tampering

Even in local development, using TLS is good practice and mirrors production security.

## Quick Start

1. Generate TLS certificates:
   ```bash
   ./tools/generate-postgres-certs.sh
   ```

2. Start PostgreSQL with TLS enabled:
   ```bash
   HIERARKEY_POSTGRES_TLS=1 docker compose up postgres
   ```

That's it! The PostgreSQL container automatically configures itself with TLS on first startup.

You can switch easily between TLS and non-TLS modes by setting or unsetting the `HIERARKEY_POSTGRES_TLS` environment variable before starting the container.

## What Happens

### Certificate Generation

The `generate-postgres-certs.sh` script creates a complete certificate chain in the `./data/postgres/certs/` directory:

- **CA (Certificate Authority)** - Self-signed root certificate
- **Server certificates** - For PostgreSQL server authentication
- **Client certificates** - For application authentication (mutual TLS)

All certificates are valid for 10 years.

## Configuration

### Application (config.toml)

```toml
[database]
url = "postgres://user@localhost:5432/dbname"

[database.tls]
enabled = true
ca_cert_path = "./data/postgres/certs/ca-cert.pem"
client_cert_path = "./data/postgres/certs/hierarkey-cert.pem"
client_key_path = "./data/postgres/certs/hierarkey-key.pem"
verify_server = true
accept_invalid_certs = false
accept_invalid_hostnames = false
```

**Key settings:**
- `enabled = true` — Turns on TLS for database connections
- `ca_cert_path` — CA certificate to verify the server's identity
- `verify_server = true` — Enforces server certificate verification (recommended)
- `accept_invalid_certs = false` — Rejects untrusted certificates (recommended)
- `accept_invalid_hostnames = false` — Rejects connections where the hostname does not match the certificate (recommended)

**Safety gate for insecure options:**

`accept_invalid_certs` and `accept_invalid_hostnames` require an explicit opt-in to take effect. You must also set:

```toml
allow_insecure_tls = true  # dev/test only — never set in production
```

Without `allow_insecure_tls = true`, setting either insecure flag to `true` will cause the server to refuse to start with a validation error.

### Client Certificates (Optional)

The `client_cert_path` and `client_key_path` settings enable **mutual TLS**, where both the server and client authenticate each other using certificates. This is optional but provides an additional security layer.

For basic TLS (server authentication only), you can omit these fields:

```toml
[database.tls]
enabled = true
ca_cert_path = "./certs/ca-cert.pem"
verify_server = true
accept_invalid_certs = false
```

## Development vs Production

### Development Setup

For local development, the self-signed certificates work fine:

```toml
[database.tls]
enabled = true
ca_cert_path = "./data/postgres/certs/ca-cert.pem"
verify_server = true
accept_invalid_certs = false
accept_invalid_hostnames = false
```

### Production Setup

For production, use certificates from a trusted Certificate Authority:

```toml
[database.tls]
enabled = true
ca_cert_path = "/etc/ssl/certs/production-ca.pem"
client_cert_path = "/etc/ssl/certs/app-client.pem"
client_key_path = "/etc/ssl/private/app-client-key.pem"
verify_server = true
accept_invalid_certs = false
accept_invalid_hostnames = false
```

Never set `accept_invalid_certs = true` or `accept_invalid_hostnames = true` in production.