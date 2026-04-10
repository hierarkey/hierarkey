# Hierarkey Tutorial – Part 6: Account and Token Management

Parts 1–5 introduced the server, secrets, RBAC, integrations, and auditing. This part covers the day-to-day admin tasks that keep users and tokens under control:

- Managing user and service accounts (list, describe, enable/disable, lock/unlock, promote/demote)
- Changing passwords and rotating service account keys
- Personal Access Tokens (PATs): creation, inspection, and revocation
- Getting short-lived tokens for service accounts in scripts

---

## 1. Listing and finding accounts

```bash
# List all regular user accounts (default)
hkey account list

# Include service accounts too
hkey account list --type service

# Include all types (users, admins, service accounts)
hkey account list --all

# Filter by status
hkey account list --status disabled
hkey account list --status locked

# Prefix filter
hkey account list --prefix svc-
```

For richer searches (label filters, date ranges, free-text):

```bash
# By label
hkey account search --label team=payments

# By type + status combination
hkey account search --type service --status active

# Text query against name/description
hkey account search --query "build bot"

# Created after a specific date
hkey account search --created-after 2026-01-01T00:00:00Z
```

---

## 2. Inspecting an account

```bash
hkey account describe --name alice
hkey account describe --name payments-api
```

The output shows the account type, status, labels, creation date, and (for service accounts) the registered public key.

---

## 3. Enabling and disabling accounts

Disable an account when it should be temporarily suspended without deleting it. Disabled accounts cannot authenticate.

```bash
hkey account disable --name alice --reason "parental leave"

# Re-enable later
hkey account enable --name alice
```

Use `disable`/`enable` for intentional suspension (e.g. offboarding, leave of absence).

---

## 4. Locking and unlocking accounts

Lock an account when you suspect a compromise or when failed-login limits require admin intervention:

```bash
hkey account lock --name alice --reason "too many failed logins"

# Lock temporarily until a specific date
hkey account lock --name alice --locked-until 2026-04-15T09:00:00Z

# Unlock manually
hkey account unlock --name alice --reason "cleared by security team"
```

The difference from `disable`: a lock can have a timestamp and is typically short-lived; a disable is an explicit administrative decision.

---

## 5. Changing passwords

Reset a user account's password:

```bash
# Generate a new random password (printed once)
hkey account change-password --name alice --generate-password

# Set a specific password (avoid — visible in shell history)
hkey account change-password --name alice --insecure-new-password "NewP@ss!"

# Force the user to set their own password at next login
hkey account change-password --name alice --generate-password --must-change-password
```

---

## 6. Promoting and demoting accounts

Grant admin privileges:

```bash
hkey account promote --name alice
```

Remove admin privileges:

```bash
hkey account demote --name alice
```

Admin accounts bypass all RBAC checks. Only promote accounts that genuinely need full platform access.

---

## 7. Personal Access Tokens (PATs)

PATs are long-lived tokens associated with the account that creates them. They are useful for scripts and CI tools that need to authenticate as a regular user without re-entering a password.

### Create a PAT

```bash
# Default lifetime: 1 hour
hkey pat create --description "local dev script"

# Longer lifetime
hkey pat create --description "quarterly automation" --ttl 90d

# With labels
hkey pat create --description "ci runner" --label env=ci --ttl 30d
```

The token is printed once. Store it securely — it cannot be retrieved again.

### List PATs

```bash
hkey pat list
```

The output includes the PAT ID, description, labels, and expiry. The token value is never shown again.

### Inspect a specific PAT

```bash
hkey pat describe --id pat_01JXXXXXXXXXXXXXXXXXXXXXXX
```

### Revoke a PAT

```bash
hkey pat revoke --id pat_01JXXXXXXXXXXXXXXXXXXXXXXX
```

Revocation is immediate. Any in-flight request using the revoked token will fail.

---

## 8. Service account tokens for scripts

Service accounts use `hkey auth sa token` to obtain a short-lived access token without a password prompt.

### Ed25519 key signature (recommended)

```bash
export HKEY_ACCESS_TOKEN=$(
  hkey auth sa token \
    --method keysig \
    --name payments-api \
    --private-key ./payments-api.pem \
    --print access-token \
    --format json \
  | jq -r .access_token
)
```

Or use the built-in env format to avoid `jq`:

```bash
eval "$(
  hkey auth sa token \
    --method keysig \
    --name payments-api \
    --private-key ./payments-api.pem \
    --format env \
    --print access-token
)"
# Now HKEY_ACCESS_TOKEN is set
```

Request a longer-lived token (capped by server policy):

```bash
hkey auth sa token \
  --method keysig \
  --name payments-api \
  --private-key ./payments-api.pem \
  --ttl 4h
```

### Passphrase (alternative)

```bash
# Interactive prompt
hkey auth sa token \
  --method passphrase \
  --name payments-api \
  --prompt-passphrase

# From stdin (useful in scripts)
echo "$SA_PASSPHRASE" | hkey auth sa token \
  --method passphrase \
  --name payments-api \
  --passphrase-stdin
```

### Write token directly to a file

```bash
hkey auth sa token \
  --method keysig \
  --name payments-api \
  --private-key ./payments-api.pem \
  --write /run/secrets/hkey-token
chmod 600 /run/secrets/hkey-token
```

---

## 9. Refreshing an access token

Access tokens have a short default lifetime (15 minutes for user logins). To extend a session without re-authenticating:

```bash
hkey auth refresh --refresh-token "$HKEY_REFRESH_TOKEN"
# Prints a new access token (and a new refresh token)
```

---

## 10. Next steps

With accounts and tokens under control, **Part 7** walks through a multi-environment promotion workflow: managing dev, staging, and prod as separate namespaces and safely promoting secrets between them.
