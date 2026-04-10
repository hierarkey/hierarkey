# Namespace Strategy

Namespaces are the primary organisational unit in Hierarkey. A good namespace design makes RBAC simple, audit logs readable, and secret sprawl manageable. A bad design makes all three painful.

---

## Namespace basics

A namespace is a hierarchical path, like a file system directory:

```
/prod/myapp
/prod/payments
/staging/myapp
/dev/myapp
```

Secrets live within a namespace. A secret's full reference is `namespace:secret-name`:

```
/prod/myapp:db/password
/prod/payments:stripe-api-key
```

RBAC rules can be scoped to a namespace and apply to all secrets within it:

```bash
hkey rbac role add --name <role> --rule "allow secret:reveal to namespace /prod/myapp"
```

This rule grants reveal access to all secrets under `/prod/myapp` — including nested ones if sub-namespaces are supported.

---

## Design principles

**1. Separate by environment first.**

The most important axis is environment. Mixing prod and non-prod secrets in the same namespace is a common mistake that leads to accidental reveals and hard-to-audit access.

```
/prod/...
/staging/...
/dev/...
```

**2. Then by team or service.**

Within each environment, organise by the team or service that owns the secrets:

```
/prod/payments
/prod/auth
/prod/data-platform
/prod/myapp
```

**3. Use flat hierarchies where possible.**

Deeply nested namespaces (`/prod/payments/europe/germany/franchise-a`) are hard to manage. Two levels (`/prod/payments`) is usually enough. Add a third level only when you have distinct teams or RBAC requirements within a service.

---

## Common patterns

### Pattern 1 — Per-environment, per-service

```
/prod/myapp        # myapp production secrets
/staging/myapp     # myapp staging secrets
/dev/myapp         # myapp dev secrets (shared)
```

Each environment gets its own service account. Promoting a secret from staging to prod means reading it from `/staging/myapp` and writing it to `/prod/myapp` — explicit and auditable.

### Pattern 2 — Per-environment, per-team

```
/prod/payments     # all production secrets owned by the payments team
/prod/auth         # all production secrets owned by the auth team
/prod/platform     # infrastructure secrets (certs, database passwords, etc.)
```

Teams manage their own namespace. Platform engineers manage `/prod/platform`. Each team creates service accounts within their namespace.

### Pattern 3 — Shared secrets namespace

For secrets shared across services (e.g. a shared database password, an internal PKI root cert):

```
/prod/shared       # cross-service secrets, managed by platform team
/prod/myapp        # app-specific secrets, managed by app team
```

Grant `secret:reveal` on `/prod/shared` to all service accounts that need it.

### Pattern 4 — Feature environment namespaces

For per-PR or per-feature-branch environments in staging:

```
/staging/feature-123
/staging/feature-456
```

Create and delete these namespaces as part of your CI/CD pipeline:

```bash
# On PR open:
hkey namespace create /staging/feature-${PR_NUMBER}
hkey secret create /staging/feature-${PR_NUMBER}:db-url --value "..."

# On PR close:
hkey namespace delete /staging/feature-${PR_NUMBER}
```

---

## RBAC alignment

The namespace structure should mirror your RBAC model. Good structures make minimal-privilege grants easy.

### Too broad — avoid

```bash
hkey rbac role add --name <role> --rule "allow secret:reveal to namespace /prod"
# This gives access to ALL prod secrets — not what you want for a single app
```

### Too narrow — hard to maintain

```bash
hkey rbac role add --name <role> --rule "allow secret:reveal to secret /prod/myapp:db/password"
hkey rbac role add --name <role> --rule "allow secret:reveal to secret /prod/myapp:api-key"
hkey rbac role add --name <role> --rule "allow secret:reveal to secret /prod/myapp:jwt-secret"
# You will add a rule every time you add a secret
```

### Just right — namespace-scoped

```bash
hkey rbac role add --name <role> --rule "allow secret:reveal to namespace /prod/myapp"
# Grants access to all current and future secrets in /prod/myapp
```

---

## Naming conventions for secrets

Within a namespace, use consistent names. Recommended conventions:

| Type | Convention | Example |
|------|-----------|---------|
| Database password | `db/password` or `database-password` | `/prod/myapp:db/password` |
| API key | `<service>-api-key` | `/prod/myapp:stripe-api-key` |
| TLS certificate + key pair | `tls/cert` and `tls/key` or a `CertificateKeyPair` type | `/prod/myapp:tls` |
| JWT signing key | `jwt-secret` | `/prod/myapp:jwt-secret` |
| Internal service credentials | `<target>-service-token` | `/prod/myapp:payments-service-token` |

Avoid embedding environment names in secret names — the namespace already carries that:

```
# Avoid:
/prod/myapp:db-prod-password     # "prod" is redundant

# Prefer:
/prod/myapp:db-password
```

---

## Migration and promotion

### Promoting secrets between environments

```bash
# Read from staging
VAL=$(hkey secret reveal /staging/myapp:db-password)

# Write to prod
hkey secret create /prod/myapp:db-password --value "$VAL"
```

Never copy the production secret down to staging. Promotion should be one-way: staging -> prod.

### Bulk namespace operations

When setting up a new environment:

```bash
# Create all namespaces at once
for svc in myapp payments auth data-platform; do
  hkey namespace create /staging/$svc
done

# Copy secrets from dev to staging (not recommended for prod)
for secret in db-password api-key jwt-secret; do
  val=$(hkey secret reveal /dev/myapp:$secret)
  hkey secret create /staging/myapp:$secret --value "$val"
done
```

---

## Governance checklist

- [ ] One namespace per (environment × service) at minimum
- [ ] RBAC rules scoped to namespace, not individual secrets
- [ ] Each service has its own service account — no shared accounts
- [ ] No service account has cross-environment access (prod account cannot read staging)
- [ ] Platform/shared secrets in a dedicated namespace with explicit grants
- [ ] Feature namespaces cleaned up on branch close
- [ ] Namespace names documented in your internal runbook
