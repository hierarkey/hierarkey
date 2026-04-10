# Hierarkey Tutorial – Part 2: Using Hierarkey with the `hkey` CLI

In **Part 1** you set up and started the **Hierarkey server**.

This part shows how to use the **`hkey` CLI** to:

- Authenticate
- Create namespaces
- Store, update, and retrieve secrets
- Work with secret revisions and labels

---

## 1. Point `hkey` at the server

Set the server URL so you don't have to pass it on every command:

```bash
export HKEY_SERVER_URL="http://localhost:8080"
```

---

## 2. Authenticate

Log in with the admin account you created during server setup:

```bash
hkey auth login --name admin
# prompts for password, then prints an access token and refresh token
```

Set the access token so all subsequent commands are authenticated:

```bash
export HKEY_ACCESS_TOKEN="hkat_..."
```

Verify you're authenticated:

```bash
hkey auth whoami
```

> **First login after bootstrap:** if you just ran `bootstrap-admin-account`, the first token you
> receive has `change_password` scope (prefix `hkcp_`) and cannot be used for any other operation.
> You must change your password first, then log in again to get a full-access token (`hkat_`):
>
> ```bash
> export HKEY_ACCESS_TOKEN="hkcp_..."   # token from first login
> hkey account change-password --name admin --insecure-new-password 'MyNewPassword!'
> hkey auth login --name admin           # login again with the new password
> export HKEY_ACCESS_TOKEN="hkat_..."   # now use this full-access token
> ```

> The default access token lifetime is 15 minutes. Use `hkey auth refresh --refresh-token <token>` to extend it without re-entering your password.

> Admin accounts bypass all RBAC checks and have full access to everything. In production, create a regular user and grant it only the permissions it needs.

---

## 3. Create your first namespace

Namespaces group secrets and each namespace has its own encryption key (KEK). Create a `/prod` namespace:

```bash
hkey namespace create \
  --namespace /prod \
  --label env=prod \
  --label owner=payments \
  --description "Production secrets for the payments stack"
```

List namespaces:

```bash
hkey namespace list
```

Describe a single namespace:

```bash
hkey namespace describe --namespace /prod
```

You can create any hierarchy that fits your needs:

```bash
hkey namespace create --namespace /prod/payments
hkey namespace create --namespace /dev
```

The only rules are: paths must start with `/`, and the `/$` prefix is reserved for system namespaces.

---

## 4. Secret addressing

Every secret is identified by a **ref** combining namespace and key path:

```
/prod:payments/api-key
│───┤ │────────────────┤
 ns       key path
```

To refer to a specific revision, append `@<number>`:

```
/prod:payments/api-key@1    # revision 1
/prod:payments/api-key@2    # revision 2
```

---

## 5. Storing secrets

### From a literal value

```bash
hkey secret create --ref /prod:payments/api-key --value "super-secret-api-key"
```

### From a file

```bash
hkey secret create --ref /prod:payments/config --from-file ./payments-config.json
```

### From stdin (binary-safe)

```bash
openssl rand 32 | hkey secret create --ref /prod:payments/key --stdin
```

### Using an editor

```bash
hkey secret create --ref /prod:payments/notes --use-editor
```

This opens `$EDITOR`, saves the value when you exit.

### With labels and description

```bash
hkey secret create \
  --ref /prod:payments/api-key \
  --value "super-secret-api-key" \
  --label env=prod \
  --label team=payments \
  --description "Payments provider API key"
```

---

## 6. Reading secrets

Reveal (decrypt) the current active revision:

```bash
hkey secret reveal --ref /prod:payments/api-key
```

Reveal a specific revision:

```bash
hkey secret reveal --ref /prod:payments/api-key@1
```

List all secrets in a namespace:

```bash
hkey secret list --namespace /prod
```

Show full details including revision history:

```bash
hkey secret describe --ref /prod:payments/api-key
```

---

## 7. Secret revisions

Every time you update a secret's value, a new **revision** is created. The old revision is never deleted — it stays available for rollback.

- First create -> revision `1`
- First revise -> revision `2`
- Next revise -> revision `3`, etc.

Create a new revision with an updated value:

```bash
hkey secret revise --ref /prod:payments/api-key --value "new-api-key-value" --note "Rotated"
```

### @active vs @latest

Two special revision selectors exist:

- `@active` — the revision that was explicitly activated. This is what `hkey secret reveal` returns by default.
- `@latest` — the most recently created revision.

When you create a new revision it immediately becomes `@latest`, but `@active` stays on the old revision until you explicitly promote it. This lets you stage a new value before committing to it:

```bash
# Current state: revision 1 is @active
hkey secret revise --ref /prod:payments/api-key --value "candidate-value"
# Now revision 2 is @latest, but revision 1 is still @active

# Reveal what applications currently see:
hkey secret reveal --ref /prod:payments/api-key         # returns revision 1 (@active)

# Reveal the staged value to test it:
hkey secret reveal --ref /prod:payments/api-key@latest  # returns revision 2

# When ready, promote the new revision:
hkey secret activate --ref /prod:payments/api-key@2
# Now revision 2 is @active — applications pick it up immediately
```

Roll back to an earlier revision the same way:

```bash
hkey secret activate --ref /prod:payments/api-key@1
```

---

## 8. Updating metadata

Update description and labels without creating a new revision:

```bash
hkey secret update --ref /prod:payments/api-key \
  --description "Updated description" \
  --label team=core-payments \
  --remove-label env
```

Other flags: `--clear-description` removes the description entirely, `--clear-labels` removes all labels.

---

## 9. Searching secrets

Search by label:

```bash
hkey secret search --label env=prod --label team=payments
```

Search by namespace prefix:

```bash
hkey secret search --namespace-prefix /prod
```

Search by key name pattern:

```bash
hkey secret search --name "api-key"
```

Combine filters as needed. By default multiple `--label` flags are ANDed together.

---

## 10. Deleting secrets

Delete a secret and all its revisions:

```bash
hkey secret delete --ref /prod:payments/api-key --confirm
```

Without `--confirm` you are prompted interactively. Deletion is a soft delete — the record is marked deleted and no longer returned by list or describe, but is retained for audit purposes.

---

## 11. Template rendering

Instead of calling `hkey secret reveal` for each secret individually, you can write a template file and render it in one pass.

Template (`config.toml.tpl`):

```toml
[database]
url = "{{ /prod:payments/database-url }}"
password = "{{ /prod:payments/db-password }}"

[api]
key = "{{ /prod:payments/api-key }}"
```

Render it:

```bash
hkey template render --file config.toml.tpl --output config.toml
```

The output file contains the real secret values — never commit it to version control. Commit only the template (`.tpl`) file. See [template-rendering.md](../guides/template-rendering.md) for full syntax and CI/CD examples.

---

You now have a working **Hierarkey + hkey** setup and a workflow for managing secrets.

Next up: RBAC and access control in **Part 3**.
