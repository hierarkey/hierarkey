# Production Deployment

A checklist-driven guide to running Hierarkey securely in production.

---

## Architecture overview

```
                    ┌─────────────────────────────────┐
                    │          Load balancer           │
                    │         (TLS termination)        │
                    └──────────────┬──────────────────┘
                                   │ HTTPS
                    ┌──────────────▼──────────────────┐
                    │         Hierarkey server         │
                    │         (one or more)            │
                    └──────────────┬──────────────────┘
                                   │ TLS
                    ┌──────────────▼──────────────────┐
                    │           PostgreSQL             │
                    └─────────────────────────────────┘
```

The server itself is stateless — all state lives in PostgreSQL. You can run multiple instances behind a load balancer from day one.

---

## 1. TLS

### Option A — TLS at the load balancer (recommended)

Terminate TLS at the load balancer (nginx, Caddy, AWS ALB, etc.) and let Hierarkey listen on plain HTTP internally. This is the simplest setup and the most common in Kubernetes or cloud environments.

Set `allow_insecure_http = true` only if the load balancer and Hierarkey are on the same trusted internal network.

### Option B — TLS at Hierarkey

Provide a certificate and key directly:

```toml
[server]
mode = "tls"
bind_address = "0.0.0.0:8443"
allow_insecure_http = false

[server.tls]
cert_file = "/etc/hierarkey/tls/server.crt"
key_file  = "/etc/hierarkey/tls/server.key"
```

Use Let's Encrypt with `certbot` or a cert-manager sidecar to keep the certificate fresh.

---

## 2. Master key

The master key encrypts all Key-Encryption Keys (KEKs). Losing it means losing all secrets.

### Passphrase backend (recommended for most deployments)

```toml
[masterkey]
default_backend   = "passphrase"
default_file_type = "passphrase"

[masterkey.file]
enabled       = true
allowed_types = ["passphrase"]
path          = "/etc/hierarkey/master-keys"
```

Bootstrap:

```bash
hierarkey bootstrap-master-key \
  --config /etc/hierarkey/config.toml \
  --provider passphrase
# You will be prompted for a passphrase — store it in your password manager
```

The passphrase is needed every time the server starts (it is used to derive the master key and is never stored on disk). Pass it at startup:

```bash
HIERARKEY_MASTERKEY_PASSPHRASE="your-passphrase" \
  hierarkey serve --config /etc/hierarkey/config.toml
```

Or via a systemd credential (see systemd section below).

### File backend (insecure — dev only)

Never use `"insecure"` file type in production. It stores the master key as plaintext on disk.

---

## 3. PostgreSQL TLS

```toml
[database]
url = "postgres://hierarkey:password@db.internal:5432/hierarkey"

[database.tls]
enabled     = true
ca_cert_path = "/etc/hierarkey/pki/db-ca.crt"
client_cert = "/etc/hierarkey/pki/db-client.crt"
client_key  = "/etc/hierarkey/pki/db-client.key"
```

Use a dedicated PostgreSQL user with the minimum required grants:

```sql
CREATE USER hierarkey WITH PASSWORD 'strong-password';
GRANT CONNECT ON DATABASE hierarkey TO hierarkey;
GRANT USAGE ON SCHEMA public TO hierarkey;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO hierarkey;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO hierarkey;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO hierarkey;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO hierarkey;
```

---

## 4. systemd unit

```ini
# /etc/systemd/system/hierarkey.service
[Unit]
Description=Hierarkey secret management server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=hierarkey
Group=hierarkey
ExecStart=/usr/local/bin/hierarkey serve --config /etc/hierarkey/config.toml
Restart=on-failure
RestartSec=5s

# Passphrase — use systemd credentials in systemd >= 250
SetCredential=masterkey-passphrase:CHANGE-ME
Environment=HIERARKEY_MASTERKEY_PASSPHRASE=%d/masterkey-passphrase

# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/etc/hierarkey/master-keys /var/log/hierarkey
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now hierarkey
```

---

## 5. Full production config

```toml
[logging]
level  = "warn"
format = "json"   # structured for log aggregators

[database]
url = "postgres://hierarkey:password@db.internal:5432/hierarkey"

[database.tls]
enabled     = true
ca_cert_path = "/etc/hierarkey/pki/db-ca.crt"
client_cert = "/etc/hierarkey/pki/db-client.crt"
client_key  = "/etc/hierarkey/pki/db-client.key"

[server]
mode                = "http"           # TLS terminated at load balancer
bind_address        = "0.0.0.0:8080"
allow_insecure_http = true

[masterkey]
default_backend   = "passphrase"
default_file_type = "passphrase"

[masterkey.file]
enabled       = true
allowed_types = ["passphrase"]
path          = "/etc/hierarkey/master-keys"
```

---

## 6. Hardening checklist

| Item | Action |
|------|--------|
| TLS in transit | Terminate at load balancer or configure `[server.tls]` |
| PostgreSQL TLS | Set `[database.tls] enabled = true` |
| Strong master key passphrase | 20+ characters, stored in a password manager |
| Master key backup | Encrypted off-site backup of `/etc/hierarkey/master-keys` AND the passphrase |
| No plaintext master key | Never use `default_file_type = "insecure"` |
| Dedicated DB user | Minimum-privilege SQL grants, no superuser |
| Non-root process | `User=hierarkey` in systemd, or non-root container user |
| `ProtectSystem=strict` | Prevent writes outside allowed paths |
| Log aggregation | Forward JSON logs to your SIEM |
| RBAC for service accounts | No service account should have `platform:admin` |
| Regular PAT audits | `hkey pat list` — revoke unused tokens |
| Healthcheck monitoring | Alert on `/readyz` returning non-200 (see [Monitoring](monitoring.md)) |

---

## 7. Running multiple instances

Hierarkey is stateless. To run multiple instances:

1. Point all instances at the same PostgreSQL database.
2. Bootstrap once — all instances share the same master key file directory (mount it as a shared volume or replicate it).
3. Put a load balancer in front (sticky sessions are not required).

If using a passphrase master key, all instances need the passphrase environment variable at startup.
