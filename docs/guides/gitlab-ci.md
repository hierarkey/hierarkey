# GitLab CI Integration

Fetch secrets from Hierarkey inside GitLab CI/CD pipelines using Ed25519 service account authentication. The same pattern as [GitHub Actions](github-actions.md), adapted for GitLab's CI syntax and variable model.

---

## How it works

```
Pipeline job
  │
  ├── 1. Write private key from GitLab CI variable to a temp file
  ├── 2. POST to Hierarkey -> receive short-lived hkat_ token (60 min)
  ├── 3. Use hkey with that token to reveal secrets
  └── 4. Token expires when the job ends
```

The private key is stored in GitLab's masked CI variables. It never leaves GitLab's secrets store.

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

The public key is stored in Hierarkey. Keep the private key safe — it is the only credential that needs protecting.

Create a narrow-scoped role and bind the service account to it:

```bash
hkey rbac role create --name ci-myapp-reader
hkey rbac role add --name ci-myapp-reader --rule "allow secret:reveal to namespace /prod/myapp"
hkey rbac bind --name ci-myapp --role ci-myapp-reader
```

---

## 2. Add variables to GitLab

In your project: **Settings > CI/CD > Variables > Add variable**

| Key | Value | Flags |
|-----|-------|-------|
| `HIERARKEY_SERVER` | `https://hierarkey.example.com` | Protected (optional) |
| `HIERARKEY_CI_PRIVATE_KEY` | Contents of `ci-myapp.priv.pem` | **Masked**, Protected |

Check **Mask variable** for the private key. GitLab will redact it from job logs.

Do not add the private key to the repository.

---

## 3. Pipeline example

```yaml
# .gitlab-ci.yml

stages:
  - deploy

deploy:
  stage: deploy
  image: ubuntu:22.04
  only:
    - main

  before_script:
    - apt-get update -qq && apt-get install -y -qq curl

    # Install hkey
    - |
      curl -sSL https://github.com/jaytaph/hierarkey/releases/latest/download/hkey-linux-amd64 \
        -o /usr/local/bin/hkey
      chmod +x /usr/local/bin/hkey

    # Authenticate with Hierarkey
    - |
      echo "$HIERARKEY_CI_PRIVATE_KEY" > /tmp/hierarkey-ci.pem
      chmod 600 /tmp/hierarkey-ci.pem
      TOKEN=$(HKEY_SERVER_URL="$HIERARKEY_SERVER" \
        hkey auth sa token \
          --method keysig \
          --name ci-myapp \
          --private-key /tmp/hierarkey-ci.pem \
          --print access-token)
      rm /tmp/hierarkey-ci.pem
      export HKEY_TOKEN="$TOKEN"
      export HKEY_SERVER_URL="$HIERARKEY_SERVER"

  script:
    - |
      DB_PASSWORD=$(hkey secret reveal /prod/myapp:db/password)
      API_KEY=$(hkey secret reveal /prod/myapp:api-key)

      echo "Deploying application..."
      # Your deploy commands using $DB_PASSWORD and $API_KEY
      # Do NOT echo these values — GitLab masks the private key but not derived secrets
```

---

## 4. Masked variables in GitLab

GitLab automatically masks the value of any CI variable marked as **Masked**. However, secrets fetched from Hierarkey at runtime are not automatically masked — GitLab only masks exact string matches of stored variable values.

To prevent secrets from appearing in logs, never `echo` secret values. Pass them as environment variables to subcommands:

```yaml
script:
  - |
    # Fetch secrets but do not echo them
    DB_PASSWORD=$(hkey secret reveal /prod/myapp:db/password)

    # Use secrets only in commands, not in echo statements
    ./deploy.sh   # passes $DB_PASSWORD as an env var internally
```

GitLab only masks exact string matches of stored CI variable values — secrets fetched at runtime are not automatically masked. The only safe approach is to never print them.

---

## 5. Using secrets in Docker builds

Pass secrets as Docker build secrets (not build args):

```yaml
script:
  - |
    DB_PASSWORD=$(hkey secret reveal /prod/myapp:db/password)
    API_KEY=$(hkey secret reveal /prod/myapp:api-key)

    docker build \
      --secret id=db_password,env=DB_PASSWORD \
      --secret id=api_key,env=API_KEY \
      -t registry.gitlab.com/mygroup/myapp:latest .
```

In the `Dockerfile`:

```dockerfile
RUN --mount=type=secret,id=db_password \
    DB_PASSWORD=$(cat /run/secrets/db_password) && \
    # use $DB_PASSWORD for build-time setup only
```

---

## 6. Deploying to Kubernetes from GitLab CI

```yaml
deploy-k8s:
  stage: deploy
  image: bitnami/kubectl:latest
  before_script:
    - |
      # Install hkey
      curl -sSL https://github.com/jaytaph/hierarkey/releases/latest/download/hkey-linux-amd64 \
        -o /usr/local/bin/hkey && chmod +x /usr/local/bin/hkey

      # Authenticate
      echo "$HIERARKEY_CI_PRIVATE_KEY" > /tmp/ci.pem && chmod 600 /tmp/ci.pem
      export HKEY_TOKEN=$(HKEY_SERVER_URL="$HIERARKEY_SERVER" \
        hkey auth sa token --method keysig --name ci-myapp --private-key /tmp/ci.pem --print access-token)
      rm /tmp/ci.pem
      export HKEY_SERVER_URL="$HIERARKEY_SERVER"

  script:
    - |
      DB_PASSWORD=$(hkey secret reveal /prod/myapp:db/password)
      API_KEY=$(hkey secret reveal /prod/myapp:api-key)

      # Sync secrets to Kubernetes
      kubectl -n myapp create secret generic myapp-secrets \
        --from-literal=db-password="$DB_PASSWORD" \
        --from-literal=api-key="$API_KEY" \
        --dry-run=client -o yaml | kubectl apply -f -
```

---

## 7. Reusable authentication snippet

Extract authentication into a reusable YAML anchor:

```yaml
.hierarkey_auth: &hierarkey_auth
  - |
    curl -sSL https://github.com/jaytaph/hierarkey/releases/latest/download/hkey-linux-amd64 \
      -o /usr/local/bin/hkey && chmod +x /usr/local/bin/hkey
    echo "$HIERARKEY_CI_PRIVATE_KEY" > /tmp/ci.pem && chmod 600 /tmp/ci.pem
    export HKEY_TOKEN=$(HKEY_SERVER_URL="$HIERARKEY_SERVER" \
      hkey auth sa token --method keysig --name ci-myapp --private-key /tmp/ci.pem --print access-token)
    rm /tmp/ci.pem
    export HKEY_SERVER_URL="$HIERARKEY_SERVER"

deploy-app:
  before_script: *hierarkey_auth
  script:
    - DB_PASSWORD=$(hkey secret reveal /prod/myapp:db/password)
    - ./deploy.sh

run-migrations:
  before_script: *hierarkey_auth
  script:
    - DB_URL=$(hkey secret reveal /prod/myapp:database-url)
    - ./migrate.sh
```

---

## 8. Least-privilege RBAC checklist

| Pipeline does | Minimum permission needed |
|---|---|
| Read secrets | `allow secret:reveal to namespace /prod/myapp` |
| List secrets | `allow secret:describe to namespace /prod/myapp` |
| Create/update secrets | `allow secret:create to namespace /prod/myapp` |
| Nothing else | Do not grant `platform:admin` or `secret:*` |

Create a separate Hierarkey service account per GitLab project or group. Shared accounts make it impossible to audit which pipeline accessed which secret.

---

## 9. Token lifetime

By default, `hkey auth sa token` issues a token valid for 60 minutes. For long-running pipelines:

```bash
TOKEN=$(HKEY_SERVER_URL="$HIERARKEY_SERVER" \
  hkey auth sa token \
    --method keysig \
    --name ci-myapp \
    --private-key /tmp/ci.pem \
    --print access-token \
    --ttl 180)   # 3 hours
```

---

## 10. Keyless authentication with GitLab CI OIDC (Commercial Edition)

> **Requires the [Hierarkey Commercial Edition](https://hierarkey.com/commercial).** Community edition uses Ed25519 key signature authentication (sections 1–9 above).

The Commercial Edition supports federated OIDC authentication. Instead of storing an Ed25519 private key in GitLab CI variables, pipelines present the GitLab-issued OIDC JWT directly to Hierarkey. No long-lived credential is stored — the JWT is minted per job and scoped to the project and branch.

### Server configuration

```toml
[[auth.federated]]
provider  = "oidc"
id        = "gitlab"
issuer    = "https://gitlab.com"          # use your self-hosted URL if applicable
audience  = "https://hierarkey.example.com"
```

### Link the service account

```bash
# Subject encodes the project path and ref
hkey account link-federated-identity \
  --name ci-myapp \
  --provider-id gitlab \
  --external-issuer "https://gitlab.com" \
  --external-subject "project_path:mygroup/myrepo:ref_type:branch:ref:main"
```

### Pipeline example

```yaml
# .gitlab-ci.yml
deploy:
  stage: deploy
  image: ubuntu:22.04
  only:
    - main

  id_tokens:
    HIERARKEY_JWT:
      aud: "https://hierarkey.example.com"   # must match the audience in server config

  before_script:
    - apt-get update -qq && apt-get install -y -qq curl jq
    - |
      curl -sSL https://github.com/jaytaph/hierarkey/releases/latest/download/hkey-linux-amd64 \
        -o /usr/local/bin/hkey && chmod +x /usr/local/bin/hkey

    - |
      export HKEY_SERVER_URL="$HIERARKEY_SERVER"
      export HKEY_TOKEN=$(hkey auth federated \
        --provider-id gitlab \
        --credential "$HIERARKEY_JWT" \
        --print access-token)

  script:
    - DB_PASSWORD=$(hkey secret reveal /prod/myapp:db/password)
    - ./deploy.sh
```

The `id_tokens` block (GitLab 15.7+) mints a short-lived JWT for the job. No private key is stored — the only CI variable needed is `HIERARKEY_SERVER`.
