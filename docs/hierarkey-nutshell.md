# Hierarkey in a nutshell

Hierarkey is a secret management platform. It securely stores sensitive secrets and keys and makes them available only to authorized users and applications.

Common use cases include storing API keys and database credentials that applications need at runtime - without hardcoding them into source code or configuration files.

It also supports rotating secrets. If an API key changes or a certificate expires, you add a new revision of the secret to Hierarkey without changing anything in the applications that read it. They automatically get the latest version.


## How does it work?

Hierarkey exposes an HTTP API. You interact with it using the `hkey` CLI tool, or directly via any HTTP client. Once authenticated, you can perform actions based on your permissions - you might be allowed to read secrets in one namespace but not another.


## What makes it secure?

Storing secrets naively - for example, as plaintext in a database - means anyone who can read the database can read every secret. Instead, Hierarkey encrypts secrets before storing them.

But where does the encryption key live? Hardcoding it in source code or a config file just moves the problem. And if a single key protects everything, compromising it exposes everything.

Hierarkey solves this with a **hierarchical encryption scheme**:

```
Master Key
  └── KEK (Key Encryption Key) - one per namespace
        └── DEK (Data Encryption Key) - one per secret version
              └── Encrypted secret value
```

**Master Key** - the root of trust. It is stored in a file encrypted with a passphrase that is never persisted anywhere. You provide the passphrase when starting the server. The master key never touches the database. Alternatively, it can be managed by a hardware security module (HSM) via PKCS#11, so the raw key material never leaves the HSM.

**KEK (Key Encryption Key)** - one per namespace, stored encrypted in the database. The master key wraps each KEK.

**DEK (Data Encryption Key)** - one per secret version, generated randomly. Each DEK is encrypted with its namespace's KEK and stored alongside the ciphertext.

**Secret value** - encrypted with the DEK using AES-256-GCM.

This layered design limits blast radius:
- A compromised DEK exposes only one secret version.
- A compromised KEK exposes only one namespace's secrets.
- A compromised database reveals nothing - everything is encrypted.
- The master key is never stored in the database.


## Rotating keys

When a key needs to change - whether because it was compromised or as routine hygiene - Hierarkey supports rotating at each layer:

- **Master key rewrap**: create a new master key and rewrap all KEKs onto it. Secret data is untouched. Done via `hkey rewrap kek`.
- **KEK rotate**: create a new KEK revision for a namespace and optionally migrate all DEKs onto it. Done via `hkey rekey kek --namespace <ns>`. Add `--migrate-deks` to rewrap DEKs in the same step.
- **Secret revision**: add a new revision of a secret value. The old revision is retained for rollback. Done via `hkey secret revise`.

Rotating keys periodically is a good security practice even when no compromise is suspected - it limits the value of any key material that may have been silently exposed.


## Secrets and revisions

Updating (or revising) a secret in Hierarkey does not overwrite the old value - it creates a new **revision**. Every revision is stored with a version number and timestamp. You can list all revisions, roll back to an earlier one, or reveal a specific revision by number.

This means a mistaken update can always be undone, and you have a full history of when each value was in use.


## Resource labels

Every resource in Hierarkey - namespaces, secrets, accounts - can carry **labels**: arbitrary key-value pairs you define. Labels let you categorize and filter resources. For example:

```
env=prod    team=backend    app=api-server
```

Labels are used for filtering and searching resources, and can be attached to namespaces, secrets, accounts, and master keys.


## Namespaces and secret references

Secrets are organized into **namespaces** - logical groups that can represent environments, teams, applications, or any structure that fits your needs. Each namespace has its own encryption key (KEK), so secrets in different namespaces are independently protected.

Example namespace hierarchy:

```
/org
/org/prod
/org/staging
/org/prod/team-alpha
```

A **secret reference** identifies a specific secret within a namespace:

```
/org/prod:app1/db/password
```

The part before `:` is the namespace path; the part after is the secret's key path within that namespace.

To refer to a specific revision, append `@<revision>`:

```
/org/prod:app1/db/password@3     # specific revision number
/org/prod:app1/db/password@active  # the currently activated revision (default)
/org/prod:app1/db/password@latest  # the most recently created revision
```

`@active` and `@latest` are not always the same. When you add a new revision it becomes `@latest`, but the previously activated revision stays `@active` until you explicitly activate the new one. This lets you stage a new secret value and activate it when ready without affecting what applications currently read.
