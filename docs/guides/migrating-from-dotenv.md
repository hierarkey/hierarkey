# Migrating from .env Files

How to move an existing application that reads secrets from `.env` files (or environment variables) to Hierarkey, with minimal changes to application code.

---

## Why migrate

| | .env files | Hierarkey |
|-|------------|-----------|
| Secrets in git | Risk of accidental commit | Secrets never in source control |
| Access control | Anyone with file access sees all secrets | Per-account, per-namespace RBAC |
| Audit trail | None | Every reveal is logged |
| Rotation | Edit file, restart app | Update secret, app re-reads on next fetch |
| Multiple environments | Multiple .env files, easy to mix up | Separate namespaces, one server |
| Secret sharing | Copy-paste or file transfer | Share by granting RBAC access |

---

## Migration strategy

There are two approaches. Choose based on how much you want to change your application code.

### Approach A — Zero code change (env-var shim)

Fetch secrets from Hierarkey at startup and inject them as environment variables before starting the application. The application keeps reading `os.environ` / `process.env` / `System.getenv` as before.

### Approach B — Native integration

Add a thin Hierarkey client to the application that fetches secrets directly. See [App Integration](app-integration.md).

Approach A is a good first step. Migrate to Approach B over time as teams become comfortable with Hierarkey.

---

## 1. Inventory your .env file

List all variables and classify them:

```bash
# Example .env
DATABASE_URL=postgres://user:secret@db:5432/myapp
REDIS_PASSWORD=secret123
API_KEY=sk-live-abc123
JWT_SECRET=supersecret
APP_ENV=production          # not a secret — a config value
LOG_LEVEL=info              # not a secret — a config value
```

Move only secrets to Hierarkey. Non-secret config values (env names, log levels, feature flags) can stay in .env or in a standard config file.

---

## 2. Create namespaces and import secrets

```bash
export HKEY_SERVER_URL=https://hierarkey.internal
export HKEY_TOKEN=hkat_...   # admin token

# Create a namespace for your app and environment
hkey namespace create /prod/myapp

# Import each secret
hkey secret create /prod/myapp:database-url    --value "postgres://user:secret@db:5432/myapp"
hkey secret create /prod/myapp:redis-password  --value "secret123"
hkey secret create /prod/myapp:api-key         --value "sk-live-abc123"
hkey secret create /prod/myapp:jwt-secret      --value "supersecret"
```

Use a consistent naming convention. Hyphens (`-`) are recommended over underscores for secret names within a namespace.

---

## 3. Create a service account

```bash
hkey account create --name myapp-prod --type service --activate

hkey rbac role create --name myapp-prod-reader
hkey rbac role add --name myapp-prod-reader --rule "allow secret:reveal to namespace /prod/myapp"
hkey rbac bind --name myapp-prod --role myapp-prod-reader
```

For local development, use a PAT:

```bash
hkey pat create --description "myapp dev token" --ttl 43200   # 30 days
# Save: hkat_...
```

For production, use Ed25519 authentication (see [App Integration](app-integration.md)).

---

## 4. Approach A — Env-var shim

Write a small wrapper script that fetches secrets and exports them before starting the application.

### Shell script shim

```bash
#!/bin/sh
# start.sh — fetch secrets from Hierarkey and exec the app

set -e

# Fetch secrets and export as env vars
export DATABASE_URL=$(hkey secret reveal /prod/myapp:database-url)
export REDIS_PASSWORD=$(hkey secret reveal /prod/myapp:redis-password)
export API_KEY=$(hkey secret reveal /prod/myapp:api-key)
export JWT_SECRET=$(hkey secret reveal /prod/myapp:jwt-secret)

# Unset Hierarkey credentials so the app cannot accidentally use them
unset HKEY_TOKEN

# Launch the actual application (replace 'node server.js' with your start command)
exec node server.js
```

```bash
chmod +x start.sh
./start.sh
```

The application starts with the secrets already in its environment. No code changes required.

### Docker entrypoint shim

```dockerfile
FROM node:20-alpine

# Install hkey
RUN curl -sSL https://github.com/jaytaph/hierarkey/releases/latest/download/hkey-linux-amd64 \
    -o /usr/local/bin/hkey && chmod +x /usr/local/bin/hkey

COPY . /app
WORKDIR /app
RUN npm ci --omit=dev

COPY start.sh /start.sh
RUN chmod +x /start.sh

ENTRYPOINT ["/start.sh"]
```

Pass `HKEY_SERVER_URL` and `HKEY_TOKEN` (or the private key) as runtime environment variables from your orchestrator.

---

## 5. Update your .env.example

Keep `.env.example` for documentation but remove actual values:

```bash
# .env.example — checked into git
# These values are now stored in Hierarkey under /prod/myapp
# See docs/guides/migrating-from-dotenv.md for setup instructions

DATABASE_URL=   # hkey secret reveal /prod/myapp:database-url
REDIS_PASSWORD= # hkey secret reveal /prod/myapp:redis-password
API_KEY=        # hkey secret reveal /prod/myapp:api-key
JWT_SECRET=     # hkey secret reveal /prod/myapp:jwt-secret

# Non-secret config (still set here or in your orchestrator)
APP_ENV=production
LOG_LEVEL=info
```

---

## 6. Update .gitignore

```gitignore
.env
.env.local
.env.*.local
# Keep .env.example (it has no values)
```

If you previously committed `.env` files, remove them from git history:

```bash
git rm --cached .env
git commit -m "remove .env from tracking (secrets now in Hierarkey)"
```

For a full history scrub, use `git filter-repo` — but coordinate with your team before rewriting shared history.

---

## 7. Local development workflow

Developers can use a local Hierarkey instance (see [Quick Start with Docker](quick-start-docker.md)) or a shared dev namespace with individual dev PATs:

```bash
# Each developer creates their own PAT
hkey auth login --name my-dev-account
hkey pat create --description "local dev" --ttl 43200

# Set in shell profile or local .env (not committed)
export HKEY_SERVER_URL=https://hierarkey-dev.internal
export HKEY_TOKEN=hkat_...
```

Optionally, keep a `.env.local` (gitignored) with just the two Hierarkey vars. The application reads secrets from Hierarkey; `.env.local` provides only the connection config.

---

## 8. Migration checklist

- [ ] Inventory all `.env` variables — separate secrets from config
- [ ] Create Hierarkey namespaces matching your environments
- [ ] Import all secrets with `hkey secret create`
- [ ] Create service accounts with minimum-required RBAC
- [ ] Write and test the shim script (or native integration)
- [ ] Update Docker images / deployment manifests
- [ ] Update `.gitignore` to exclude `.env`
- [ ] Remove `.env` from git tracking
- [ ] Update developer onboarding docs
- [ ] Verify no secrets remain in CI/CD environment variables
- [ ] Delete the old `.env` files from servers
