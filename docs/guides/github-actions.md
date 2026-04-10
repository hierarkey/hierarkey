# GitHub Actions Integration

Fetch secrets from Hierarkey inside GitHub Actions workflows using Ed25519 service account authentication. This avoids storing long-lived tokens in GitHub — the only credential stored is the private key, which is used to get a short-lived token at runtime.

## How it works

```
Workflow run
  │
  ├── 1. Generate Ed25519 token request (signed with private key)
  ├── 2. POST to Hierarkey -> receive short-lived hkat_ token (60 min)
  ├── 3. Use hkey with that token to reveal secrets
  └── 4. Token expires automatically when the run ends
```

The private key never leaves GitHub's secrets store. There is no long-lived token to rotate or accidentally leak in logs.

---

## 1. Set up the service account in Hierarkey

Generate an Ed25519 key pair first — the public key is registered when the account is created:

```bash
openssl genpkey -algorithm ed25519 -out ci-myapp.priv.pem
openssl pkey -in ci-myapp.priv.pem -pubout -out ci-myapp.pub.pem
```

Create the service account and register the public key:

```bash
hkey account create --name ci-myapp --type service \
  --public-key-file ci-myapp.pub.pem --activate
```

The public key is stored in Hierarkey. **Keep the private key file safe — it is the only credential that needs protecting.**

Create a narrow-scoped role and bind the service account to it:

```bash
hkey rbac role create --name ci-myapp-reader
hkey rbac role add --name ci-myapp-reader --rule "allow secret:reveal to namespace /prod/myapp"
hkey rbac bind --name ci-myapp --role ci-myapp-reader
```

---

## 2. Add the private key to GitHub Secrets

In your repository: **Settings > Secrets and variables > Actions > New repository secret**

| Name | Value |
|------|-------|
| `HIERARKEY_SERVER` | `https://hierarkey.example.com` |
| `HIERARKEY_CI_PRIVATE_KEY` | contents of `ci-myapp.priv.pem` |

Do not add the private key to the repository or any artifact.

---

## 3. Workflow example

```yaml
name: Deploy

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Install hkey
        run: |
          curl -sSL https://github.com/jaytaph/hierarkey/releases/latest/download/hkey-linux-amd64 \
            -o /usr/local/bin/hkey
          chmod +x /usr/local/bin/hkey

      - name: Authenticate with Hierarkey
        env:
          HKEY_SERVER_URL: ${{ secrets.HIERARKEY_SERVER }}
        run: |
          # Write the private key to a temporary file
          echo "${{ secrets.HIERARKEY_CI_PRIVATE_KEY }}" > /tmp/hierarkey-ci.pem
          chmod 600 /tmp/hierarkey-ci.pem

          # Exchange the private key for a short-lived token
          TOKEN=$(hkey auth sa token \
            --method keysig \
            --name ci-myapp \
            --private-key /tmp/hierarkey-ci.pem \
            --print access-token)

          # Remove the private key immediately after use
          rm /tmp/hierarkey-ci.pem

          # Export the token for subsequent steps
          echo "HKEY_TOKEN=${TOKEN}" >> "$GITHUB_ENV"

      - name: Fetch secrets
        env:
          HKEY_SERVER_URL: ${{ secrets.HIERARKEY_SERVER }}
        run: |
          DB_PASSWORD=$(hkey secret reveal /prod/myapp:db/password)
          API_KEY=$(hkey secret reveal /prod/myapp:api-key)

          # Store in GITHUB_ENV for subsequent steps
          # GitHub Actions masks any value added this way in logs
          echo "DB_PASSWORD=${DB_PASSWORD}" >> "$GITHUB_ENV"
          echo "API_KEY=${API_KEY}"         >> "$GITHUB_ENV"

      - name: Build and deploy
        env:
          HKEY_SERVER_URL: ${{ secrets.HIERARKEY_SERVER }}
        run: |
          echo "Deploying with DB_PASSWORD and API_KEY available..."
          # Your deploy commands here
```

---

## 4. Using secrets in Docker builds

If you need secrets available during a `docker build`, pass them as build secrets (not build args — build args end up in the image history):

```yaml
      - name: Build image
        run: |
          docker build \
            --secret id=db_password,env=DB_PASSWORD \
            --secret id=api_key,env=API_KEY \
            -t myapp:latest .
```

In the `Dockerfile`:

```dockerfile
RUN --mount=type=secret,id=db_password \
    DB_PASSWORD=$(cat /run/secrets/db_password) && \
    # use $DB_PASSWORD for build-time setup only
```

For runtime secrets, bake nothing into the image — let the app fetch them at startup using the patterns in [App Integration](app-integration.md).

---

## 5. Deploying to Kubernetes

Combine the workflow above with `kubectl` to create Kubernetes Secrets from Hierarkey values:

```yaml
      - name: Sync secrets to Kubernetes
        run: |
          kubectl -n myapp create secret generic myapp-secrets \
            --from-literal=db-password="$DB_PASSWORD" \
            --from-literal=api-key="$API_KEY" \
            --dry-run=client -o yaml | kubectl apply -f -
```

The `--dry-run=client -o yaml | kubectl apply` pattern is idempotent — safe to run on every deployment.

---

## 6. Least-privilege RBAC checklist

| Workflow does | Minimum permission needed |
|---|---|
| Read secrets | `allow secret:reveal to namespace /prod/myapp` |
| List secrets | `allow secret:describe to namespace /prod/myapp` |
| Create/update secrets (e.g. store a build artifact) | `allow secret:create to namespace /prod/myapp` |
| Nothing else | Do not grant `platform:admin` or `secret:*` |

Create a separate Hierarkey service account per repository or per team. Shared accounts make it impossible to audit which workflow accessed which secret.

---

## 7. Token lifetime

By default `hkey auth sa token` issues a token valid for 60 minutes. A typical GitHub Actions workflow completes well within that window. If you have very long-running jobs, request a longer TTL:

```bash
TOKEN=$(hkey auth sa token \
  --method keysig \
  --name ci-myapp \
  --private-key /tmp/hierarkey-ci.pem \
  --print access-token \
  --ttl 180)   # 3 hours
```

The token is automatically invalid after expiry — no cleanup needed.

---

## 8. Keyless authentication with GitHub OIDC (Commercial Edition)

> **Requires the [Hierarkey Commercial Edition](https://hierarkey.com/commercial).** Community edition uses Ed25519 key signature authentication (sections 1–7 above).

The Commercial Edition supports federated OIDC authentication. Instead of storing an Ed25519 private key in GitHub Secrets, workflows present the GitHub-issued OIDC JWT directly to Hierarkey. No long-lived credential is stored anywhere — the JWT is minted fresh for every run and is scoped to the specific repository and branch.

### Server configuration

Add a federated provider to `hierarkey-config.toml`:

```toml
[[auth.federated]]
provider  = "oidc"
id        = "github"
issuer    = "https://token.actions.githubusercontent.com"
audience  = "https://hierarkey.example.com"   # must match the `aud` you request in the workflow
```

### Link the service account

```bash
# The subject encodes the repo and ref — adjust the pattern for your branch/tag strategy
hkey account link-federated-identity \
  --name ci-myapp \
  --provider-id github \
  --external-issuer "https://token.actions.githubusercontent.com" \
  --external-subject "repo:myorg/myrepo:ref:refs/heads/main"
```

To allow any branch in the repo (useful for PRs and release branches), link with a ref prefix — see the `link-federated-identity` help for subject pattern options.

### Workflow example

```yaml
name: Deploy

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest

    permissions:
      id-token: write   # required to request an OIDC token
      contents: read

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Install hkey
        run: |
          curl -sSL https://github.com/jaytaph/hierarkey/releases/latest/download/hkey-linux-amd64 \
            -o /usr/local/bin/hkey
          chmod +x /usr/local/bin/hkey

      - name: Authenticate with Hierarkey (OIDC)
        env:
          HKEY_SERVER_URL: ${{ secrets.HIERARKEY_SERVER }}
        run: |
          # Request a GitHub OIDC token scoped to the Hierarkey server URL
          OIDC_TOKEN=$(curl -sSfL \
            -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
            "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=https://hierarkey.example.com" \
            | jq -r '.value')

          # Exchange the OIDC token for a Hierarkey access token
          TOKEN=$(hkey auth federated \
            --provider-id github \
            --credential "$OIDC_TOKEN" \
            --print access-token)

          echo "HKEY_TOKEN=${TOKEN}" >> "$GITHUB_ENV"

      - name: Fetch secrets
        env:
          HKEY_SERVER_URL: ${{ secrets.HIERARKEY_SERVER }}
        run: |
          DB_PASSWORD=$(hkey secret reveal /prod/myapp:db/password)
          echo "DB_PASSWORD=${DB_PASSWORD}" >> "$GITHUB_ENV"
```

No private key, no secret rotation, no credential to leak — the only stored configuration is `HIERARKEY_SERVER`.
