# Quick Start with Docker

Get a fully working Hierarkey installation running locally in about five minutes using Docker Compose.

## Prerequisites

- Docker and Docker Compose
- The `hkey` CLI ([download](https://github.com/hierarkey/hierarkey/releases) or build from source)

---

## 1. Create the project directory

```bash
mkdir hierarkey-local && cd hierarkey-local
mkdir -p data/master-keys
```

---

## 2. Write the Docker Compose file

```yaml
# docker-compose.yml
services:
  postgres:
    image: postgres:16
    environment:
      POSTGRES_DB: hierarkey
      POSTGRES_USER: hierarkey
      POSTGRES_PASSWORD: dev_password
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U hierarkey"]
      interval: 5s
      retries: 10

  hierarkey:
    image: hierarkey/hierarkey:latest
    depends_on:
      postgres:
        condition: service_healthy
    ports:
      - "8080:8080"
    volumes:
      - ./hierarkey-config.toml:/app/hierarkey-config.toml:ro
      - ./data:/app/data
    command: serve --config /app/hierarkey-config.toml

volumes:
  pgdata:
```

---

## 3. Write the config file

```toml
# hierarkey-config.toml

[logging]
level = "info"

[database]
url = "postgres://hierarkey:dev_password@postgres:5432/hierarkey"

[database.tls]
enabled = false

[server]
mode = "http"
bind_address = "0.0.0.0:8080"
allow_insecure_http = true

[masterkey]
default_backend = "file"
default_file_type = "insecure"

[masterkey.file]
enabled = true
allowed_types = ["insecure"]
path = "/app/data/master-keys"
```

> This config uses an insecure (plaintext) master key and plain HTTP. It is intentionally minimal for local development. Do not use it in production.

---

## 4. Bootstrap

Start the database first, then run the three one-time setup commands:

```bash
# Start only postgres so we can run the bootstrap commands
docker compose up -d postgres

# Apply database migrations
docker compose run --rm hierarkey hierarkey update-migrations \
  --config /app/hierarkey-config.toml

# Create the master key
docker compose run --rm hierarkey hierarkey bootstrap-master-key \
  --config /app/hierarkey-config.toml \
  --provider insecure

# Create the first admin account (you will be prompted for a password)
docker compose run --rm hierarkey hierarkey bootstrap-admin-account \
  --config /app/hierarkey-config.toml \
  --name admin
```

Bootstrap only needs to run once. The data persists in the `pgdata` Docker volume.

---

## 5. Start the server

```bash
docker compose up -d hierarkey
```

Verify it is running:

```bash
curl http://localhost:8080/healthz
# {"status":"ok"}
```

---

## 6. Connect with hkey

```bash
export HKEY_SERVER_URL=http://localhost:8080

# Log in as admin
hkey auth login --name admin
# Enter the password you chose during bootstrap
# The access token is printed — copy it

export HKEY_TOKEN=hkat_...   # paste your token here

# Confirm you are connected
hkey auth whoami
```

---

## 7. Store and retrieve your first secret

```bash
# Create a namespace
hkey namespace create /dev

# Store a secret
hkey secret create /dev:app/db-password --value "supersecret123"

# Read it back
hkey secret reveal /dev:app/db-password
```

---

## 8. Stopping and restarting

```bash
# Stop everything (data is preserved in the Docker volume)
docker compose down

# Start again later — no bootstrap needed
docker compose up -d
```

---

## Next steps

- [App Integration](app-integration.md) — fetch secrets from Python or Go code
- [Kubernetes Sidecar](kubernetes-sidecar.md) — run Hierarkey-aware workloads in Kubernetes
- [Tutorial Part 2](../tutorial/hierarkey_part2_namespace_and_secrets.md) — namespaces, revisions, metadata
- [Tutorial Part 3](../tutorial/hierarkey_part3_rbac.md) — RBAC and access control
