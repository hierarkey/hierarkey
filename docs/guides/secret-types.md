# Secret Types

Hierarkey validates and stores typed secrets. Specifying the correct type allows Hierarkey to reject malformed values at write time — catching mistakes before they silently break production.

---

## Overview

| Type | Description | Validation |
|------|-------------|-----------|
| `opaque` | Arbitrary binary or text data | None |
| `password` | Password string | None (any value accepted) |
| `json` | JSON document | Must be valid JSON |
| `yaml` | YAML document | Must be valid YAML |
| `jwt` | JSON Web Token | Must have 3 base64url parts; header must contain `alg` |
| `certificate` | Single X.509 certificate (PEM) | Must contain exactly one `CERTIFICATE` PEM block |
| `certificate_chain` | X.509 certificate chain (PEM) | Must contain one or more `CERTIFICATE` PEM blocks |
| `certificate_key_pair` | Certificate + matching private key | Certificate and key must match cryptographically |
| `private_key` | Private key (PEM) | Must be a recognised PEM private key format |
| `public_key` | Public key (PEM) | Must be a recognised PEM public key format |
| `ssh_private_key` | OpenSSH private key | Must be a valid OpenSSH private key |
| `uri` | URI (any scheme) | Must be a valid URI |
| `connection_string` | Database or service connection URI | Must use a recognised database scheme |

Secret values are always passed as base64-encoded bytes in the API. The `hkey` CLI handles encoding transparently.

---

## `opaque`

Accepts any data: binary files, unstructured text, arbitrary blobs. Use this as a last resort when no other type fits.

```bash
hkey secret create /prod/myapp:raw-data --type opaque --value "some arbitrary value"
```

---

## `password`

A plain password string. No structural validation is applied — any non-empty value is accepted. Using this type over `opaque` makes the intent explicit in audit logs and listings.

```bash
hkey secret create /prod/myapp:db-password --type password --value "s3cret!Pass"
```

---

## `json`

A valid JSON document. Hierarkey validates the structure on write. Useful for structured configuration blobs.

```bash
hkey secret create /prod/myapp:feature-flags \
  --type json \
  --value '{"dark_mode": true, "max_requests": 100}'
```

The value must be a valid JSON value — object, array, string, number, boolean, or null.

---

## `yaml`

A valid YAML document.

```bash
hkey secret create /prod/myapp:app-config \
  --type yaml \
  --value $'database:\n  host: db.internal\n  port: 5432'
```

---

## `jwt`

A JSON Web Token in `header.payload.signature` format. Hierarkey validates that:
- The token has exactly three base64url-encoded parts.
- The header decodes to a JSON object containing an `"alg"` field.

Note: Hierarkey does **not** verify the signature — it only validates the structure.

```bash
hkey secret create /prod/myapp:service-jwt \
  --type jwt \
  --value "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.sig"
```

---

## `certificate`

A single X.509 certificate in PEM format.

```bash
hkey secret create /prod/myapp:tls-cert \
  --type certificate \
  --value "$(cat server.crt)"
```

The value must contain exactly one `-----BEGIN CERTIFICATE-----` block.

---

## `certificate_chain`

One or more X.509 certificates in PEM format, concatenated. Use this for intermediate + leaf certificate chains.

```bash
hkey secret create /prod/myapp:tls-chain \
  --type certificate_chain \
  --value "$(cat fullchain.pem)"
```

---

## `certificate_key_pair`

A certificate and its matching private key in a single PEM blob. Hierarkey validates:
- Exactly one `CERTIFICATE` PEM block is present.
- Exactly one private key block is present.
- For PKCS#8 keys (Ed25519, ECDSA P-256, ECDSA P-384): the private key cryptographically matches the certificate's public key.

```bash
# Concatenate cert and key into a single value
BUNDLE=$(cat server.crt server.key)
hkey secret create /prod/myapp:tls \
  --type certificate_key_pair \
  --value "$BUNDLE"
```

The order of certificate and key in the bundle does not matter.

---

## `private_key`

A private key in PEM format. Accepted formats:

| PEM label | Format |
|-----------|--------|
| `PRIVATE KEY` | PKCS#8 (any algorithm) |
| `RSA PRIVATE KEY` | Legacy RSA |
| `EC PRIVATE KEY` | Legacy EC |
| `DSA PRIVATE KEY` | Legacy DSA |
| `ENCRYPTED PRIVATE KEY` | PKCS#8 encrypted |

```bash
hkey secret create /prod/myapp:signing-key \
  --type private_key \
  --value "$(cat signing.key)"
```

---

## `public_key`

A public key in PEM format. Accepted formats:

| PEM label | Format |
|-----------|--------|
| `PUBLIC KEY` | PKCS#8 (any algorithm) |
| `RSA PUBLIC KEY` | Legacy RSA |

```bash
hkey secret create /prod/myapp:verification-key \
  --type public_key \
  --value "$(cat signing.pub)"
```

---

## `ssh_private_key`

An OpenSSH private key. The value must begin with `-----BEGIN OPENSSH PRIVATE KEY-----` and decode to a blob starting with the `openssh-key-v1` magic bytes.

```bash
hkey secret create /prod/myapp:deploy-key \
  --type ssh_private_key \
  --value "$(cat ~/.ssh/id_ed25519)"
```

---

## `uri`

A valid URI with any scheme. Useful for webhook URLs, OAuth callback URIs, or any URL-typed config.

```bash
hkey secret create /prod/myapp:webhook-url \
  --type uri \
  --value "https://hooks.example.com/incoming/abc123"
```

---

## `connection_string`

A database or service connection URI. Hierarkey validates both structure and scheme. Accepted schemes:

`postgres`, `postgresql`, `mysql`, `mariadb`, `redis`, `rediss`, `mongodb`, `mongodb+srv`, `amqp`, `amqps`, `cassandra`, `elasticsearch`, `kafka`, `memcached`, `couchdb`, `neo4j`, `bolt`

```bash
hkey secret create /prod/myapp:database-url \
  --type connection_string \
  --value "postgres://user:password@db.internal:5432/myapp"
```

This is the recommended type for database URLs. Using `uri` instead would accept any scheme; `connection_string` provides a tighter constraint.

---

## Choosing a type

When in doubt, use the most specific type that fits:

```
connection_string > uri > opaque         (for URLs)
certificate_key_pair > certificate        (for TLS)
private_key > opaque                      (for keys)
json > yaml > opaque                      (for config blobs)
password > opaque                         (for passwords)
```

Use `opaque` only when nothing else fits. Typed secrets produce better error messages and more useful audit log entries.

---

## Listing secrets by type

```bash
# List all connection strings in a namespace
hkey secret list /prod/myapp --type connection_string

# List all certificates
hkey secret list /prod/myapp --type certificate
```
