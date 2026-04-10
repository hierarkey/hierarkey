# Hierarkey Tutorial – Part 8: Going to Production

Parts 1–7 covered development setups, RBAC, integrations, auditing, account management, and multi-environment workflows. This part turns the knobs that matter before you expose Hierarkey to real traffic.

For full configuration reference see [production-deployment.md](../guides/production-deployment.md).

---

## 1. What changes between dev and prod

| Concern | Dev tutorial setup | Production setup |
|---|---|---|
| Master key | `insecure` (plaintext on disk) | `passphrase` (key wrapped with a strong passphrase) |
| HTTP | Plain HTTP, `allow_insecure_http = true` | HTTPS at load balancer or `[server.tls]` |
| Database TLS | Disabled | Enabled with CA cert |
| Logging | `info`, text format | `warn`, JSON format |
| Process user | Your dev user | Dedicated `hierarkey` system user |

---

## 2. The master key passphrase

The dev tutorial used an `insecure` master key — the key material is stored in plaintext. Before going to production, switch to a passphrase-protected key.

### Bootstrap with a passphrase

Run this once on a fresh database (or after wiping the dev master key):

```bash
hierarkey bootstrap-master-key \
  --config /etc/hierarkey/config.toml \
  --provider passphrase
# Prompted for passphrase — use 20+ random characters
# Store it in your password manager and an encrypted backup
```

### Config changes

```toml
[masterkey]
default_backend   = "file"
default_file_type = "passphrase"

[masterkey.file]
enabled       = true
allowed_types = ["passphrase"]
path          = "/etc/hierarkey/master-keys"
```

The passphrase is required every time the server starts. Pass it as an environment variable:

```bash
HIERARKEY_MASTERKEY_PASSPHRASE="your-strong-passphrase" \
  hierarkey serve --config /etc/hierarkey/config.toml
```

Never put the passphrase in the config file or in a world-readable environment.

---

## 3. TLS

### Option A — TLS at the load balancer (recommended)

Keep `mode = "http"` on the Hierarkey server and terminate TLS at nginx, Caddy, an AWS ALB, or an ingress controller. The connection between the load balancer and Hierarkey stays on a trusted internal network.

```toml
[server]
mode                = "http"
bind_address        = "127.0.0.1:8080"
allow_insecure_http = true
```

### Option B — TLS at the server

Provide a certificate and key:

```toml
[server]
mode                = "tls"
bind_address        = "0.0.0.0:8443"
allow_insecure_http = false

[server.tls]
cert_file = "/etc/hierarkey/tls/server.crt"
key_file  = "/etc/hierarkey/tls/server.key"
```

---

## 4. PostgreSQL TLS

Enable TLS for the database connection and use a minimum-privilege database user:

```toml
[database]
url = "postgres://hierarkey:strong-password@db.internal:5432/hierarkey"

[database.tls]
enabled      = true
ca_cert_path = "/etc/hierarkey/pki/db-ca.crt"
```

See [production-deployment.md](../guides/production-deployment.md) for the minimal SQL grants to use.

---

## 5. Logging

Switch to structured JSON logging so your log aggregator (Loki, Elasticsearch, Splunk, etc.) can parse and index fields:

```toml
[logging]
level  = "warn"
format = "json"
```

Forward logs to your SIEM or alerting pipeline. Watch for:
- Authentication failures
- `permission_denied` access events
- Server startup/shutdown
- Master key operations

---

## 6. Running as a systemd service

Create a dedicated system user:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin hierarkey
sudo mkdir -p /etc/hierarkey/master-keys /var/log/hierarkey
sudo chown hierarkey:hierarkey /etc/hierarkey/master-keys /var/log/hierarkey
sudo chmod 700 /etc/hierarkey/master-keys
```

Create the unit file at `/etc/systemd/system/hierarkey.service`:

```ini
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

# Master key passphrase — use systemd credentials (systemd >= 250)
# or a secrets manager integration to avoid plaintext in the unit file.
# For a simple setup, use an EnvironmentFile with restricted permissions:
EnvironmentFile=/etc/hierarkey/secrets.env   # contains HIERARKEY_MASTERKEY_PASSPHRASE=...

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
# /etc/hierarkey/secrets.env  (mode 0600, owner hierarkey)
HIERARKEY_MASTERKEY_PASSPHRASE=your-strong-passphrase
```

```bash
sudo chmod 600 /etc/hierarkey/secrets.env
sudo chown hierarkey:hierarkey /etc/hierarkey/secrets.env

sudo systemctl daemon-reload
sudo systemctl enable --now hierarkey
sudo systemctl status hierarkey
```

Verify the health endpoint:

```bash
curl https://hierarkey.example.com/healthz
curl https://hierarkey.example.com/readyz
```

---

## 7. Run database migrations before each deployment

Always run migrations before starting the new binary:

```bash
hierarkey check-migrations --config /etc/hierarkey/config.toml
hierarkey update-migrations --config /etc/hierarkey/config.toml
```

This is safe to run on an already-migrated database (it is a no-op if nothing is pending).

---

## 8. Backups

Hierarkey's state lives entirely in PostgreSQL. Back up:

1. **The database** — standard `pg_dump` or continuous WAL archiving. Restore point should be consistent.
2. **The master key directory** (`/etc/hierarkey/master-keys`) — an encrypted copy stored separately from the database backup. The database backup is useless without the master key, and the master key is useless without the database.
3. **The master key passphrase** — stored in your team password manager, separate from the key file.

See [backup-and-restore.md](../guides/backup-and-restore.md) for restore procedures.

---

## 9. Pre-launch hardening checklist

| | Item |
|---|---|
| ☐ | TLS enabled between clients and Hierarkey (load balancer or `[server.tls]`) |
| ☐ | TLS enabled for the PostgreSQL connection |
| ☐ | Master key uses `passphrase` type, not `insecure` |
| ☐ | Passphrase is 20+ characters and stored in a password manager |
| ☐ | Encrypted off-site backup of master key directory AND passphrase |
| ☐ | Dedicated, minimum-privilege PostgreSQL user |
| ☐ | Server runs as a non-root system user |
| ☐ | `ProtectSystem=strict` (or equivalent container security context) |
| ☐ | Logging in JSON format, forwarded to log aggregator |
| ☐ | Admin account password is strong and stored securely |
| ☐ | No service account has `platform:admin` |
| ☐ | Health endpoint (`/readyz`) monitored with alerting |
| ☐ | `hkey pat list` run — no stale or unexplained PATs |
| ☐ | RBAC reviewed — principle of least privilege applied to all accounts |

---

## 10. Where to go from here

You now have a production-ready Hierarkey deployment. For ongoing operations:

- [Master key management](../guides/master-key-management.md) — rotation, backup, and recovery procedures
- [Monitoring](../guides/monitoring.md) — health endpoints and alerting
- [Backup and restore](../guides/backup-and-restore.md) — disaster recovery
- [Production deployment](../guides/production-deployment.md) — full config reference and multi-instance setup
