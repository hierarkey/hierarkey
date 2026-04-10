# Hierarkey Tutorial – Part 1: Setting up the Hierarkey Server

Hierarkey is a central secret management service with:

- A **server** (`hierarkey`) that stores and encrypts secrets
- A **CLI** (`hkey`) to interact with it

This part covers setting up the **Hierarkey server**.
Part 2 covers using it with the **`hkey` CLI**.

---

## 1. Prerequisites

You'll need:

- **PostgreSQL 15+**, reachable from your server
- The **`hierarkey` server binary** and **`hkey` CLI binary** (built from source)
- **`jq`** — used in later tutorial parts for JSON processing (`apt install jq` / `brew install jq`)

For this tutorial we'll use:

- Postgres on `localhost:5432`
- A local config file: `server-config.toml`
- A file-based master key with no passphrase (`insecure` type — for development only)

---

## 2. Build the binaries

```bash
git clone https://github.com/hierarkey/hierarkey.git
cd hierarkey
cargo build --release
```

Add the binaries to your `PATH` so the rest of the tutorial commands work without full paths:

```bash
export PATH="$PWD/target/release:$PATH"
# hierarkey  — server binary
# hkey       — CLI client
```

---

## 3. Prepare the PostgreSQL database

Create a dedicated database and user:

```bash
psql -h localhost -U postgres
```

Inside `psql`:

```sql
CREATE DATABASE hierarkey;
CREATE USER hierarkey WITH PASSWORD 'change_me_strong_password';
GRANT ALL PRIVILEGES ON DATABASE hierarkey TO hierarkey;
```

> **Using docker-compose?** The repo ships a `docker-compose.yaml` that starts PostgreSQL for you
> (`docker compose up -d`). It creates the `hierarkey` database, user, and password automatically.
> However, be aware: the compose file bind-mounts `./data` into the container, which causes Docker
> to create that directory as `root`. Do **not** use `data/master-keys` as your master key path
> when running docker-compose — use a separate directory such as `./master-keys` instead (see step 4).
> If you ever destroy and recreate the compose stack, drop the named volumes too
> (`docker compose down -v`) before re-running the bootstrap commands, otherwise the database will
> already contain a master key record while the key file on disk is gone.

---

## 4. Generate a configuration file

The server ships with a `generate-config` command that writes a fully commented template:

```bash
hierarkey generate-config --output server-config.toml
```

Then edit `server-config.toml`. At minimum, update these sections for local development:

```toml
[logging]
level = "info"

[database]
url = "postgres://hierarkey:change_me_strong_password@localhost:5432/hierarkey"

[database.tls]
enabled = false          # Disable TLS for local dev (not recommended for production)

[server]
mode = "http"
bind_address = "127.0.0.1:8080"
allow_insecure_http = true   # Required safety flag for HTTP mode

[masterkey]
default_backend = "file"
default_file_type = "insecure"   # Dev only — use "passphrase" for production
allow_insecure_masterkey = true  # Required when using the "insecure" provider

[masterkey.file]
enabled = true
allowed_types = ["insecure"]
path = "master-keys"             # Avoid "data/" if using docker-compose (see step 3)
```

> **Development note**: The `insecure` master key type stores the key in plaintext. Never use it in production. For production, use `default_file_type = "passphrase"` or the `pkcs11` backend.

---

## 5. Run database migrations

Check that migrations are up to date:

```bash
hierarkey check-migrations --config server-config.toml
```

Apply any pending migrations:

```bash
hierarkey update-migrations --config server-config.toml --yes
```

> Without `--yes` the command prompts for interactive confirmation (`yes/no`) before proceeding.
> Pass `--yes` to skip the prompt in scripts or automated setups.

This creates the necessary tables for namespaces, secrets, KEKs, accounts, tokens, RBAC, and audit logs.

---

## 6. Bootstrap the master key

Create the first master key. This key will be used to wrap all namespace KEKs:

```bash
hierarkey bootstrap-master-key \
  --config server-config.toml \
  --usage wrap_kek \
  --provider insecure
```

This command fails if a master key already exists, so it is safe to run on a fresh database.

---

## 7. Bootstrap the first admin account

Create the initial admin account:

```bash
hierarkey bootstrap-admin-account \
  --config server-config.toml \
  --name admin
```

The server **generates a random password** and prints it once — copy it, you will need it in
step 9. This command fails if an admin account already exists.

---

## 8. Start the server

```bash
hierarkey serve --config server-config.toml
```

The server will warn that you are running with an insecure master key and over plain HTTP. This is expected for this tutorial setup.

The server listens on `http://localhost:8080`. You can verify it's up:

```bash
curl http://localhost:8080/healthz
```

---

## 9. Change the admin password

The first login with the generated password returns a **restricted token** with `change_password`
scope only. You must change your password before doing anything else:

```bash
# 1. Login — the token printed here has change_password scope only
hkey --server http://localhost:8080 auth login --name admin
export HKEY_ACCESS_TOKEN=hkcp_...   # use the token printed above

# 2. Change password
hkey account change-password --name admin --insecure-new-password 'MyNewPassword!'

# 3. Login again — this time you get a full-access token
hkey --server http://localhost:8080 auth login --name admin
export HKEY_ACCESS_TOKEN=hkat_...
```

---

Continue with **Part 2** to manage namespaces and secrets using the `hkey` CLI.
