# Hierarkey Tutorial – Part 7: Multi-Environment Promotion Workflow

Most teams manage at least three environments: **dev**, **staging**, and **prod**. This part shows how to model them in Hierarkey and safely promote secret values from one environment to the next.

---

## 1. Namespace structure

Use a namespace per environment. Each namespace gets its own encryption key (KEK), so a breach of the dev key never exposes prod secrets:

```
/dev
/dev/payments
/dev/checkout

/staging
/staging/payments
/staging/checkout

/prod
/prod/payments
/prod/checkout
```

Create the top-level namespaces first:

```bash
hkey namespace create --namespace /dev       --label env=dev
hkey namespace create --namespace /staging   --label env=staging
hkey namespace create --namespace /prod      --label env=prod

hkey namespace create --namespace /dev/payments
hkey namespace create --namespace /staging/payments
hkey namespace create --namespace /prod/payments
```

---

## 2. RBAC per environment

### Recommended role set

| Role | Rules | Used by |
|---|---|---|
| `dev-payments-writer` | `allow secret:* to namespace /dev/payments` | developers |
| `staging-payments-writer` | `allow secret:* to namespace /staging/payments` | CI pipeline |
| `prod-payments-reader` | `allow secret:reveal,list to namespace /prod/payments` | application service accounts |
| `prod-payments-deployer` | `allow secret:revise,create to namespace /prod/payments` | release pipeline |

Create them:

```bash
# Dev: developers can do everything in dev
hkey rbac role create --name dev-payments-writer
hkey rbac role add --name dev-payments-writer \
  --rule "allow secret:* to namespace /dev/payments"

# Staging: CI pipeline can write
hkey rbac role create --name staging-payments-writer
hkey rbac role add --name staging-payments-writer \
  --rule "allow secret:* to namespace /staging/payments"

# Prod: apps can only read
hkey rbac role create --name prod-payments-reader
hkey rbac role add --name prod-payments-reader \
  --rule "allow secret:reveal to namespace /prod/payments"
hkey rbac role add --name prod-payments-reader \
  --rule "allow secret:list to namespace /prod/payments"

# Prod: release pipeline can add revisions but not delete
hkey rbac role create --name prod-payments-deployer
hkey rbac role add --name prod-payments-deployer \
  --rule "allow secret:create to namespace /prod/payments"
hkey rbac role add --name prod-payments-deployer \
  --rule "allow secret:revise to namespace /prod/payments"
```

Bind accounts:

```bash
# Developers get write access to dev only
hkey rbac bind --account alice --role dev-payments-writer

# CI service account gets write access to staging
hkey rbac bind --account ci-staging --role staging-payments-writer

# Application service account reads prod
hkey rbac bind --account payments-api --role prod-payments-reader

# Release service account promotes to prod
hkey rbac bind --account ci-prod-deploy --role prod-payments-deployer
```

---

## 3. Storing secrets per environment

Store separate values for each environment. Secret keys follow the same path; only the namespace differs:

```bash
# Dev (developer sets an easy placeholder value)
hkey secret create --ref /dev/payments:db/password \
  --value "dev-only-password" \
  --label env=dev

# Staging (CI or ops sets a real test value)
hkey secret create --ref /staging/payments:db/password \
  --value "staging-db-pass" \
  --label env=staging

# Prod (ops sets the real value)
hkey secret create --ref /prod/payments:db/password \
  --value "$(cat /tmp/prod-db-pass.txt)" \
  --label env=prod
```

Each namespace has an independent encryption key so prod secrets are never accessible from dev credentials.

---

## 4. Promoting a secret value to production

"Promotion" means adding a new revision of the prod secret with the value you've validated in staging.

### Step 1 — Validate in staging

Reveal the staging value:

```bash
STAGING_VAL=$(hkey secret reveal --ref /staging/payments:db/password)
```

Run your integration or smoke tests against staging using that value.

### Step 2 — Stage the new prod revision

Once validated, add the new value as a staged revision in prod:

```bash
hkey secret revise \
  --ref /prod/payments:db/password \
  --value "$STAGING_VAL" \
  --note "Promoted from staging 2026-04-10"
```

At this point `@latest` points to the new revision but `@active` still serves the old value to running applications.

### Step 3 — Verify the staged revision

```bash
# What apps currently receive
hkey secret reveal --ref /prod/payments:db/password

# The staged candidate
hkey secret reveal --ref /prod/payments:db/password@latest
```

### Step 4 — Activate (cut over)

```bash
hkey secret activate --ref /prod/payments:db/password@latest
```

All subsequent `reveal` calls (without a revision selector) will return the new value. If your application re-reads secrets on every request or on a configurable interval, it picks up the change without a restart.

### Rolling back

If the new value causes problems, roll back to the previous revision:

```bash
# Find the revision number you want
hkey secret describe --ref /prod/payments:db/password

# Activate the old revision
hkey secret activate --ref /prod/payments:db/password@1
```

---

## 5. CI/CD promotion pipeline example

A GitHub Actions workflow that promotes a secret from staging to prod when a release is tagged:

```yaml
name: Promote secrets to prod

on:
  push:
    tags: [ 'v*' ]

jobs:
  promote:
    runs-on: ubuntu-latest
    env:
      HKEY_SERVER_URL: https://hierarkey.example.com

    steps:
      - name: Install hkey CLI
        run: |
          curl -L -o hkey https://releases.example.com/hkey-linux-amd64
          chmod +x hkey && sudo mv hkey /usr/local/bin/

      - name: Authenticate to staging (read)
        run: |
          eval "$(
            hkey auth sa token \
              --method keysig \
              --name ci-staging \
              --private-key <(echo "${{ secrets.CI_STAGING_PRIVKEY }}") \
              --format env --print access-token
          )"
          echo "HKEY_ACCESS_TOKEN=$HKEY_ACCESS_TOKEN" >> "$GITHUB_ENV"

      - name: Read validated staging secrets
        run: |
          DB_PASS="$(hkey secret reveal --ref /staging/payments:db/password)"
          API_KEY="$(hkey secret reveal --ref /staging/payments:api-key)"
          # Pass values to the next step via a temp file (avoid env variable leakage)
          printf '%s\n%s' "$DB_PASS" "$API_KEY" > /tmp/promoted-values

      - name: Authenticate to prod (write)
        run: |
          eval "$(
            hkey auth sa token \
              --method keysig \
              --name ci-prod-deploy \
              --private-key <(echo "${{ secrets.CI_PROD_PRIVKEY }}") \
              --format env --print access-token
          )"
          echo "HKEY_ACCESS_TOKEN=$HKEY_ACCESS_TOKEN" >> "$GITHUB_ENV"

      - name: Stage new prod revision
        run: |
          DB_PASS=$(sed -n '1p' /tmp/promoted-values)
          API_KEY=$(sed -n '2p' /tmp/promoted-values)

          hkey secret revise \
            --ref /prod/payments:db/password \
            --value "$DB_PASS" \
            --note "Released ${{ github.ref_name }}"

          hkey secret revise \
            --ref /prod/payments:api-key \
            --value "$API_KEY" \
            --note "Released ${{ github.ref_name }}"

      - name: Activate prod revisions
        run: |
          hkey secret activate --ref /prod/payments:db/password@latest
          hkey secret activate --ref /prod/payments:api-key@latest
```

---

## 6. Keeping environments in sync

Over time environments drift — new secrets get added to dev but not yet to staging or prod. A quick way to find gaps:

```bash
# List just the key names in each namespace and compare
diff \
  <(hkey secret list --namespace /dev/payments --json | jq -r '.entries[].ref_key' | sort) \
  <(hkey secret list --namespace /prod/payments --json | jq -r '.entries[].ref_key' | sort)
```

> **Note:** Avoid diffing the plain `hkey secret list` table output — it includes IDs, sizes, and
> ages that will always differ between namespaces, making the diff unreadable. The `--json` +
> `jq` approach above extracts just the secret names for a clean comparison.

Establish a convention: new secrets are always created in all three environments simultaneously. Use placeholder values in dev and staging until real values are available.

---

## 7. Next steps

**Part 8** covers production hardening: TLS termination, systemd service management, backups, and a security checklist before you go live.
