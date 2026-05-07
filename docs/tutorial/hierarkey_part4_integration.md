# Hierarkey Tutorial – Part 4: Using Hierarkey in Apps, CI/CD, and Kubernetes

In the first three parts you:

- Set up the **Hierarkey server** (Part 1)
- Used the **`hkey` CLI** to manage secrets (Part 2)
- Configured **RBAC & permissions** (Part 3)

This part focuses on **how to consume secrets from Hierarkey** in practice:

- From local scripts and services
- From CI/CD pipelines
- From Kubernetes workloads

---

## 1. Design principles

1. **Hierarkey is the source of truth**
   Secrets live in Hierarkey first. Other systems are projections.

2. **Minimize secret lifetime outside Hierarkey**
   Don't bake secrets into images. Avoid writing plaintext secrets to disk. If you must write to disk, keep it short-lived and locked down.

3. **Use narrow-scoped service accounts**
   CI/CD and apps use dedicated Hierarkey service accounts with precise RBAC roles.

4. **Automate rotation**
   Rotations should be scripted and repeatable, not manual.

---

## 2. Using Hierarkey from a local app or script

### 2.1 Inject as environment variable

```bash
export HKEY_SERVER_URL="https://hierarkey.example.com"
export HKEY_ACCESS_TOKEN="hkat_..."

export PAYMENTS_DB_PASSWORD="$(
  hkey secret reveal --ref /prod/payments:db/password
)"

./run-payments-service
```

### 2.2 Render a config file from secrets

```bash
export HKEY_SERVER_URL="https://hierarkey.example.com"
export HKEY_ACCESS_TOKEN="hkat_..."

DB_PASSWORD="$(hkey secret reveal --ref /prod/payments:db/password)"
API_KEY="$(hkey secret reveal --ref /prod/payments:api-key)"

cat > config.yml <<EOF
database:
  host: db.prod.internal
  user: payments
  password: ${DB_PASSWORD}

api:
  key: ${API_KEY}
EOF

./run-payments-service --config config.yml
```

---

## 3. Using Hierarkey from CI/CD

### 3.1 GitHub Actions example

Store a Hierarkey service account access token in GitHub Actions Secrets (e.g. `HIERARKEY_TOKEN`), then use `hkey` in the pipeline:

```yaml
name: Deploy payments service

on:
  push:
    branches: [ main ]

jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      HKEY_SERVER_URL: https://hierarkey.example.com
      HKEY_ACCESS_TOKEN: ${{ secrets.HIERARKEY_TOKEN }}

    steps:
      - name: Checkout repo
        uses: actions/checkout@v4

      - name: Install hkey CLI
        run: |
          curl -L -o hkey https://github.com/hierarkey/hierarkey/releases/latest/download/hkey-linux-amd64
          chmod +x hkey
          sudo mv hkey /usr/local/bin/

      - name: Fetch secrets from Hierarkey
        run: |
          DB_PASSWORD="$(hkey secret reveal --ref /prod/payments:db/password)"
          API_KEY="$(hkey secret reveal --ref /prod/payments:api-key)"

          printf '%s' "$DB_PASSWORD" > db_password.txt
          printf '%s' "$API_KEY"     > api_key.txt

      - name: Apply Kubernetes Secret
        run: |
          kubectl -n payments create secret generic payments-secrets \
            --from-file=db-password=./db_password.txt \
            --from-file=api-key=./api_key.txt \
            --dry-run=client -o yaml | kubectl apply -f -
```

The CI service account (`ci-payments-deploy`) should have only:

```
allow secret:reveal to namespace /prod/payments
allow secret:list to namespace /prod/payments
```

---

## 4. Using Hierarkey with Kubernetes

### Pattern A — CI/CD syncs secrets to Kubernetes Secrets

CI fetches from Hierarkey and applies a `kubectl create secret`. Kubernetes workloads see normal `Secret` objects and don't know about Hierarkey.

Pros: simple, no in-cluster Hierarkey dependency.
Cons: secrets live in two places; rotations require a CI run.

### Pattern B — Init container fetches directly from Hierarkey

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: payments
  namespace: payments
spec:
  volumes:
    - name: secrets-vol
      emptyDir: {}
  initContainers:
    - name: fetch-secrets
      image: your-registry/hkey-runner:latest
      env:
        - name: HKEY_SERVER_URL
          value: "https://hierarkey.example.com"
        - name: HKEY_ACCESS_TOKEN
          valueFrom:
            secretKeyRef:
              name: hierarkey-token
              key: token
      volumeMounts:
        - name: secrets-vol
          mountPath: /secrets
      command: ["/bin/sh", "-c"]
      args:
        - |
          set -e
          hkey secret reveal --ref /prod/payments:db/password > /secrets/db-password
          hkey secret reveal --ref /prod/payments:api-key      > /secrets/api-key
  containers:
    - name: payments
      image: your-registry/payments-service:latest
      volumeMounts:
        - name: secrets-vol
          mountPath: /run/secrets
```

Pros: secrets never exist as Kubernetes `Secret` objects; rotating in Hierarkey takes effect on the next pod restart.
Cons: requires storing a Hierarkey token inside a Kubernetes `Secret` to bootstrap the init container.

---

## 5. Secret rotation workflow

### Database password rotation

1. Rotate the password in the database (`ALTER USER payments PASSWORD '...'`).
2. Revise the secret in Hierarkey:
   ```bash
   hkey secret revise --ref /prod/payments:db/password \
     --value "NewPassword2025!" \
     --note "Quarterly rotation"
   ```
3. Trigger a rollout (redeploy pods or CI run).
4. Verify the app uses the new password.
5. Remove the old password in the database.

---

## 6. Recommended RBAC setup for integrations

| Service account | Role | Rules |
|---|---|---|
| `ci-payments-deploy` | `ci-payments-reader` | `allow secret:reveal to namespace /prod/payments` |
| `k8s-payments-pod` | `k8s-payments-reader` | `allow secret:reveal to namespace /prod/payments` |
| Developers | `dev-payments-writer` | `allow secret:* to namespace /dev/payments` |

Create service accounts with Ed25519 keypairs so they can authenticate without long-lived passwords:

```bash
hkey account create \
  --type service --name ci-payments-deploy \
  --auth ed25519 --generate-keypair --out-private-key ./ci-payments-deploy.pem \
  --activate

hkey account create \
  --type service --name k8s-payments-pod \
  --auth ed25519 --generate-keypair --out-private-key ./k8s-payments-pod.pem \
  --activate
```

Store each `.pem` file where the service runs — a GitHub Actions secret, a Kubernetes Secret, etc. To get a token at runtime:

```bash
hkey auth sa token \
  --method keysig \
  --name ci-payments-deploy \
  --private-key ./ci-payments-deploy.pem
```

---

## 7. Key rotation

Rotating keys periodically limits the blast radius of any key material that has been silently exposed. Hierarkey supports rotation at three independent layers.

### 7.1 Rotating a secret value (application-level)

When an API key, database password, or certificate changes:

```bash
# Add the new value as a revision — @active stays on the old value
hkey secret revise \
  --ref /prod/payments:db/password \
  --value "NewPassword2025!" \
  --note "Q4 rotation"

# Test applications against the new value (via @latest) if your setup allows it

# Promote the new revision to @active
hkey secret activate --ref /prod/payments:db/password@latest
```

### 7.2 Rotating a namespace KEK

KEK rotation re-encrypts all DEKs in a namespace under a new key. The secret _values_ are untouched; only the DEK wrappers are re-encrypted. Use this periodically or after suspected exposure of a namespace key.

```bash
# Create a new KEK revision and immediately migrate all DEKs to it
hkey rekey kek --namespace /prod/payments --migrate-deks --yes
```

To preview what will happen first:

```bash
hkey rekey kek --namespace /prod/payments --migrate-deks --dry-run
```

The `--yes` flag skips the interactive confirmation prompt. Omit it to confirm manually. The old KEK is retired automatically once all DEKs have been migrated.

### 7.3 Rotating the master key

Rotate the master key when the passphrase may be compromised, when migrating to an HSM, or on a scheduled interval. This re-wraps all namespace KEKs under the new master key; secret values are untouched.

```bash
# 1. Create the new master key with a fresh passphrase
hkey masterkey create \
  --name new-primary \
  --usage wrap_kek \
  --provider passphrase \
  --generate-passphrase

# 2. Activate it — the old key moves to "draining" state
hkey masterkey activate --name new-primary

# 3. Rewrap all KEKs from the old key to the new active one
#    Run until the output reports the old key is retired
hkey rewrap kek --from old-primary

# 4. Verify
hkey masterkey status
hkey namespace list
```

Save the new passphrase securely before the server restarts. After rotation, update the passphrase in your deployment environment (environment variable, secrets manager, etc.).

---

## 8. Summary

You have a full path from "Hierarkey server is running" to "real workloads safely consume secrets":

- Local apps and scripts use `hkey secret reveal` to inject secrets.
- CI/CD pipelines use a service account token and sync secrets into Kubernetes.
- Pods can fetch secrets directly from Hierarkey via init containers.
- Keys rotate at every layer — secret values, namespace KEKs, and the master key — independently and without downtime.

Continue with **Part 5** for auditing and compliance workflows.
