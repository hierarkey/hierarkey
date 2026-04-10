# Hierarkey Tutorial – Part 3: RBAC & Permissions

In Parts 1 and 2 you set up the server and managed secrets as an admin. Admin accounts bypass all access checks. In real deployments you'll want scoped accounts that can only access what they need.

This part explains how **Role-Based Access Control (RBAC)** works in Hierarkey.

---

## 1. RBAC overview

Hierarkey RBAC has three building blocks:

- **Rule** — a single policy statement: `allow secret:reveal to namespace /prod/**`
- **Role** — a named group of rules: `prod-reader`
- **Binding** — attaches an account to a role

Access is **default deny**. If no rule matches, the request is denied.

When a request comes in:

1. The server authenticates the token and resolves the account.
2. Looks up all roles bound to that account.
3. Collects all rules from those roles.
4. Evaluates whether any rule permits the requested action.

See [rbac.md](../rbac.md) for the full rule syntax and evaluation semantics.

---

## 2. Permissions

Permissions are `resource:action` tokens. The most common ones:

**Secret permissions:**
- `secret:reveal` — decrypt and return a secret value
- `secret:list` — list secrets in a namespace
- `secret:describe` — read secret metadata
- `secret:create` — create a new secret
- `secret:revise` — add a new revision
- `secret:delete` — delete a secret
- `secret:update:meta` — update labels/description without a new revision
- `secret:*` — all secret permissions

**Namespace permissions:**
- `namespace:list` — list namespaces
- `namespace:describe` — read namespace metadata
- `namespace:create` — create a namespace
- `namespace:*` — all namespace permissions

**Platform permissions:**
- `audit:read` — read audit events
- `rbac:admin` — manage roles, rules, and bindings platform-wide
- `platform:admin` — full superuser access

---

## 3. Creating roles and rules

Create a read-only role for the payments namespace:

```bash
# 1. Create the role
hkey rbac role create --name prod-payments-reader \
  --description "Read-only access to payments secrets in prod"

# 2. Add a rule to it
hkey rbac role add --name prod-payments-reader \
  --rule "allow secret:reveal to namespace /prod/payments"

hkey rbac role add --name prod-payments-reader \
  --rule "allow secret:list to namespace /prod/payments"
```

Create a read/write role:

```bash
hkey rbac role create --name prod-payments-writer \
  --description "Read/write access to payments secrets in prod"

hkey rbac role add --name prod-payments-writer \
  --rule "allow secret:reveal to namespace /prod/payments"

hkey rbac role add --name prod-payments-writer \
  --rule "allow secret:list to namespace /prod/payments"

hkey rbac role add --name prod-payments-writer \
  --rule "allow secret:create to namespace /prod/payments"

hkey rbac role add --name prod-payments-writer \
  --rule "allow secret:revise to namespace /prod/payments"
```

Or use a wildcard to grant all secret permissions at once:

```bash
hkey rbac role add --name prod-payments-writer \
  --rule "allow secret:* to namespace /prod/payments"
```

---

## 4. Binding roles to accounts

Assuming you have accounts `alice` and `payments-api`:

```bash
# Give alice read/write
hkey rbac bind --name alice --role prod-payments-writer

# Give the service account read-only
hkey rbac bind --name payments-api --role prod-payments-reader
```

Service accounts bind the same way as regular accounts.

---

## 5. Service account authentication

Regular user accounts log in with a password via `hkey auth login`. Service accounts use a separate token endpoint with one of two auth methods.

### Method A — Ed25519 key signature (recommended)

No long-lived password to manage. The server stores only the public key; the private key never leaves your machine.

```bash
# Create the service account and generate a keypair in one step
hkey account create \
  --type service \
  --name payments-api \
  --auth ed25519 \
  --generate-keypair \
  --out-private-key ./payments-api.pem \
  --activate

# Authenticate and capture the token
export HKEY_ACCESS_TOKEN=$(
  hkey auth sa token \
    --method keysig \
    --name payments-api \
    --private-key ./payments-api.pem \
  | jq -r .access_token
)
```

Store `payments-api.pem` wherever the service runs (Kubernetes Secret, CI secret variable, etc.). The public key is registered in Hierarkey; the private key is used only to sign the auth challenge.

### Method B — Passphrase

```bash
# Create with a generated passphrase (printed once)
hkey account create \
  --type service \
  --name payments-api \
  --auth passphrase \
  --generate-passphrase \
  --print-secret-once \
  --activate

# Authenticate (prompts for passphrase interactively)
hkey auth sa token \
  --method passphrase \
  --name payments-api \
  --prompt-passphrase
```

---

## 6. Checking bindings and explaining access

List all bindings for an account:

```bash
hkey rbac bindings --account alice
```

Remove a binding:

```bash
hkey rbac unbind --name alice --role prod-payments-writer
```

Explain why a specific access would be allowed or denied:

```bash
hkey rbac explain --account alice --permission secret:reveal --secret /prod/payments:db/password

hkey rbac explain --account payments-api --permission secret:reveal --secret /prod/payments:db/password
```

The explain output shows which rule matched (or why nothing matched) and the final decision.

---

## 7. Common RBAC patterns

### Environment-based isolation

Developers can read everywhere but cannot delete in prod:

```bash
hkey rbac role create --name dev-reader
hkey rbac role add --name dev-reader --rule "allow secret:reveal to namespace /prod/**"
hkey rbac role add --name dev-reader --rule "allow secret:* to namespace /dev/**"
hkey rbac role add --name dev-reader --rule "deny secret:delete to namespace /prod/**"
```

### Service account scoped to one path

`payments-api` can only reveal secrets under `/prod/payments`:

```bash
hkey rbac role create --name svc-payments-reader
hkey rbac role add --name svc-payments-reader \
  --rule "allow secret:reveal to namespace /prod/payments"

hkey rbac bind --name payments-api --role svc-payments-reader
```

### Admin carve-out: full access except deletes in prod

```bash
hkey rbac role create --name prod-admin-no-delete
hkey rbac role add --name prod-admin-no-delete \
  --rule "allow secret:* to namespace /prod/**"
hkey rbac role add --name prod-admin-no-delete \
  --rule "deny secret:delete to namespace /prod/**"
```

### Namespace policy delegate

An account that can manage RBAC only within a specific namespace:

```bash
hkey rbac role create --name ns-policy-manager
hkey rbac role add --name ns-policy-manager \
  --rule "allow namespace:policy:read to namespace /prod"
hkey rbac role add --name ns-policy-manager \
  --rule "allow namespace:policy:write to namespace /prod"
```

---

## 8. End-to-end example

Goal: Alice (developer) can read/write payments secrets in prod. The `payments-api` service can only read them.

```bash
# Create a namespace and a test secret (as admin)
hkey namespace create --namespace /prod/payments
hkey secret create --ref /prod/payments:db/password --value "s3cr3t"

# Create accounts
hkey account create --type user --name alice --generate-password --activate
hkey account create \
  --type service --name payments-api \
  --auth ed25519 --generate-keypair --out-private-key ./payments-api.pem \
  --activate

# Create roles
hkey rbac role create --name prod-payments-reader
hkey rbac role add --name prod-payments-reader \
  --rule "allow secret:reveal to namespace /prod/payments"
hkey rbac role add --name prod-payments-reader \
  --rule "allow secret:list to namespace /prod/payments"

hkey rbac role create --name prod-payments-writer
hkey rbac role add --name prod-payments-writer \
  --rule "allow secret:* to namespace /prod/payments"

# Bind roles
hkey rbac bind --name alice --role prod-payments-writer
hkey rbac bind --name payments-api --role prod-payments-reader
```

### Verify the setup works

Confirm the policy looks right before testing:

```bash
hkey rbac explain --account alice --permission secret:reveal --secret /prod/payments:db/password
hkey rbac explain --account payments-api --permission secret:reveal --secret /prod/payments:db/password
```

Now actually test it by logging in as each account:

```bash
# Save the admin token to restore later
ADMIN_TOKEN="$HKEY_ACCESS_TOKEN"

# ---- Test alice (writer) ----
hkey auth login --name alice    # enter the generated password
export HKEY_ACCESS_TOKEN="hkat_..."

hkey secret reveal --ref /prod/payments:db/password   # should succeed
hkey secret revise --ref /prod/payments:db/password --value "new-s3cr3t"   # should succeed

# ---- Test payments-api (read-only) ----
export HKEY_ACCESS_TOKEN=$(
  hkey auth sa token --method keysig --name payments-api --private-key ./payments-api.pem \
  | jq -r .access_token
)

hkey secret reveal --ref /prod/payments:db/password   # should succeed
hkey secret revise --ref /prod/payments:db/password --value "x"   # should fail: permission denied

# ---- Restore admin ----
export HKEY_ACCESS_TOKEN="$ADMIN_TOKEN"
```

---

## 9. Next steps

You now have a working RBAC setup. Next up: integrating Hierarkey with apps, CI/CD, and Kubernetes in **Part 4**.
