# Multi-Environment Patterns

How to manage secrets across development, staging, and production environments using Hierarkey namespaces, RBAC, and promotion workflows.

---

## Namespace layout

The recommended layout separates environments at the top level:

```
/prod/myapp          # production secrets
/staging/myapp       # staging secrets
/dev/myapp           # shared dev secrets (or per-developer)
```

Separate environments at the namespace level, not the secret-name level. This makes RBAC simple and access grants explicit.

---

## Service accounts per environment

Each environment gets its own service account. A production service account **never** has access to dev or staging namespaces, and vice versa.

```bash
# Production service account
hkey account create --name myapp-prod --type service --activate
hkey rbac role create --name myapp-prod-reader
hkey rbac role add --name myapp-prod-reader --rule "allow secret:reveal to namespace /prod/myapp"
hkey rbac bind --name myapp-prod --role myapp-prod-reader

# Staging service account
hkey account create --name myapp-staging --type service --activate
hkey rbac role create --name myapp-staging-reader
hkey rbac role add --name myapp-staging-reader --rule "allow secret:reveal to namespace /staging/myapp"
hkey rbac bind --name myapp-staging --role myapp-staging-reader

# Dev service account (or use per-developer PATs)
hkey account create --name myapp-dev --type service --activate
hkey rbac role create --name myapp-dev-reader
hkey rbac role add --name myapp-dev-reader --rule "allow secret:reveal to namespace /dev/myapp"
hkey rbac bind --name myapp-dev --role myapp-dev-reader
```

---

## Initial secret population

When setting up a new environment, populate secrets explicitly. Do not copy production values to lower environments:

```bash
# Staging (use staging-appropriate values — not prod passwords)
hkey secret create /staging/myapp:database-url \
  --value "postgres://myapp:staging-pass@staging-db:5432/myapp"
hkey secret create /staging/myapp:api-key \
  --value "sk-staging-abc123"

# Production (use real values)
hkey secret create /prod/myapp:database-url \
  --value "postgres://myapp:prod-pass@prod-db:5432/myapp"
hkey secret create /prod/myapp:api-key \
  --value "sk-live-xyz789"
```

---

## Promotion workflow

Promoting a secret means copying the value from one environment to another. This should be a deliberate, tracked action.

### Manual promotion

```bash
# Read from staging
VAL=$(hkey secret reveal /staging/myapp:api-key)

# Write to production (creates a new revision if secret exists)
hkey secret revise /prod/myapp:api-key --value "$VAL"
```

### CI/CD promotion script

```bash
#!/bin/bash
# promote.sh — promote a secret from one environment to another
set -euo pipefail

SRC_NS="$1"    # e.g. /staging/myapp
DST_NS="$2"    # e.g. /prod/myapp
SECRET="$3"    # e.g. api-key

VAL=$(hkey secret reveal "${SRC_NS}:${SECRET}")
hkey secret revise "${DST_NS}:${SECRET}" --value "$VAL" \
  --note "Promoted from ${SRC_NS} by ${USER} on $(date -u +%Y-%m-%dT%H:%M:%SZ)"

echo "Promoted ${SECRET} from ${SRC_NS} to ${DST_NS}"
```

```bash
./promote.sh /staging/myapp /prod/myapp api-key
```

The `--note` creates a revision audit trail showing where the value came from.

---

## Feature environment namespaces

For ephemeral per-branch or per-PR environments:

```bash
# On PR open (in CI)
PR_NUMBER=${CI_MERGE_REQUEST_IID}
hkey namespace create /staging/feature-${PR_NUMBER}

# Copy baseline secrets from staging
for secret in database-url redis-password api-key; do
  val=$(hkey secret reveal /staging/myapp:${secret})
  hkey secret create /staging/feature-${PR_NUMBER}:${secret} --value "$val"
done

# Create a short-lived service account for this feature environment
hkey account create --name myapp-feat-${PR_NUMBER} --type service --activate
hkey rbac role create --name feat-${PR_NUMBER}-reader
hkey rbac role add --name feat-${PR_NUMBER}-reader --rule "allow secret:reveal to namespace /staging/feature-${PR_NUMBER}"
hkey rbac bind --name myapp-feat-${PR_NUMBER} --role feat-${PR_NUMBER}-reader
```

```bash
# On PR close (in CI)
hkey namespace delete /staging/feature-${PR_NUMBER}
# Deleting the namespace also deletes all secrets within it
```

---

## Developer-local patterns

### Option A — Shared dev namespace

All developers use the same dev namespace with a shared service account or individual PATs scoped to `/dev/myapp`:

```bash
# Each developer gets a PAT
hkey auth login --name my-username
hkey pat create --description "local dev $(date +%Y%m%d)" --ttl 43200
```

Works well for small teams. Risk: one developer's changes affect everyone in the namespace.

### Option B — Per-developer namespaces

Each developer gets their own namespace:

```bash
# Namespace per developer
hkey namespace create /dev/alice/myapp
hkey namespace create /dev/bob/myapp

# Each developer manages their own namespace — create a role for them
hkey rbac role create --name alice-dev-admin
hkey rbac role add --name alice-dev-admin --rule "allow secret:* to namespace /dev/alice/myapp"
hkey rbac bind --name alice --role alice-dev-admin
```

More isolation, more setup. Useful when developers need different secret values (e.g. different API keys with different quotas).

### Option C — Local Hierarkey instance

Developers run a local Hierarkey with Docker Compose (see [Quick Start with Docker](quick-start-docker.md)). Complete isolation, no shared state.

```bash
# Each developer runs locally
docker compose up -d

# Namespace mirrors production layout
hkey namespace create /prod/myapp
hkey secret create /prod/myapp:database-url --value "postgres://..."
```

The application config is identical between environments — only `HKEY_SERVER_URL` changes.

---

## Environment-agnostic application config

Design your application to be environment-agnostic: the only config difference between environments is `HKEY_SERVER_URL` and the authentication credential. Secret names are the same in every environment:

```python
# Same code in dev, staging, and production
DB_URL = reveal_secret("/prod/myapp:database-url")
```

Wait — this hard-codes `/prod/` in the code. Better: use an environment variable for the namespace prefix:

```python
import os

NAMESPACE = os.environ.get("APP_NAMESPACE", "/prod/myapp")

DB_URL   = reveal_secret(f"{NAMESPACE}:database-url")
API_KEY  = reveal_secret(f"{NAMESPACE}:api-key")
```

Set `APP_NAMESPACE` in your deployment:

| Environment | `APP_NAMESPACE` |
|-------------|----------------|
| Production | `/prod/myapp` |
| Staging | `/staging/myapp` |
| Development | `/dev/myapp` |
| Feature PR #42 | `/staging/feature-42` |

The application code is identical across all environments.

---

## Cross-environment RBAC summary

| Account | Access |
|---------|--------|
| `myapp-prod` | `secret:reveal` on `/prod/myapp` only |
| `myapp-staging` | `secret:reveal` on `/staging/myapp` only |
| `myapp-dev` | `secret:reveal` on `/dev/myapp` only |
| `ci-myapp` | `secret:reveal` on `/staging/myapp` (for integration tests) |
| `platform-admin` | Full access to all namespaces (break-glass only) |
| Individual developers | PATs scoped to `/dev/myapp` or `/dev/<username>/myapp` |

No service account should have cross-environment access. If a production account needs staging data, that is a design smell — reconsider the architecture.

---

## Checklist

- [ ] One namespace per (environment × service)
- [ ] One service account per (environment × service)
- [ ] No service account with cross-environment access
- [ ] `APP_NAMESPACE` (or equivalent) set at deployment time, not in code
- [ ] Feature namespaces deleted on branch close
- [ ] Promotion is always one-way (lower -> higher environment)
- [ ] Production values never copied down to lower environments
