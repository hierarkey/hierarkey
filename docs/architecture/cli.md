# CLI (hkey)

**Binary**: `hkey` | **Crate**: `hierarkey-cli`

The `hkey` CLI is a thin HTTP client that wraps the Hierarkey API. It reads the server URL from `--server <URL>` or the `HKEY_SERVER_URL` environment variable.

Authentication tokens are passed via `--token` or the `HKEY_ACCESS_TOKEN` environment variable.

---

## Global Options

```
hkey [OPTIONS] <COMMAND>

Options:
  --server <URL>       API server URL (env: HKEY_SERVER_URL)
  --token <TOKEN>      Bearer token (env: HKEY_ACCESS_TOKEN)
  --self-signed        Accept self-signed TLS certificates
  -v, --verbose        Enable debug logging
  --json               Output raw JSON instead of formatted text
  --table              Output in table format (if supported)
```

---

## Commands

### auth

```
hkey auth login           --name <name> [--ttl <duration>] [--mfa-code <code>] [--env]
hkey auth refresh
hkey auth whoami
hkey auth sa token        --method <passphrase|mtls|keysig> [--name <name>]
                          [--private-key <file>] [--ttl <duration>]
                          [--print access-token|refresh-token|expires-in]
hkey auth federated       --provider-id <id>
                          [--credential-file <path>|--credential <token>]
                          [--print access-token]
hkey auth list-providers
```

`login` returns a JSON object with `access_token`, `refresh_token`, etc. Use `--env` for eval-friendly output or `--json` for scripting.

For Ed25519 service account authentication:

```bash
TOKEN=$(hkey auth sa token --method keysig --name myapp --private-key myapp.pem --print access-token)
```

### account

```
hkey account create                    --type user|service --name <name>
                                       [--activate] [--generate-password|--insecure-password <pw>]
                                       [--public-key-file <path>]
hkey account list
hkey account search                    [<query>]
hkey account describe                  [--name <name>|--id <id>]
hkey account change-password           [--name <name>|--id <id>]
hkey account promote                   [--name <name>|--id <id>]
hkey account demote                    [--name <name>|--id <id>]
hkey account lock                      [--name <name>|--id <id>] [--reason <reason>]
hkey account unlock                    [--name <name>|--id <id>]
hkey account enable                    [--name <name>|--id <id>]
hkey account disable                   [--name <name>|--id <id>] [--reason <reason>]
hkey account link-federated-identity   --name <name> --provider-id <id>
                                       --external-issuer <url> --external-subject <subject>
hkey account describe-federated-identity  --name <name>
hkey account unlink-federated-identity --name <name>
```

`set-cert` (mTLS client certificate) is a Commercial Edition feature.

### namespace

```
hkey namespace create   -n <path> [--label <k=v>...] [--description <desc>]
hkey namespace describe [-n <path>|--id <id>]
hkey namespace update   [-n <path>|--id <id>] [--label <k=v>...] [--description <desc>]
hkey namespace delete   [-n <path>|--id <id>]
hkey namespace disable  [-n <path>|--id <id>]
hkey namespace enable   [-n <path>|--id <id>]
hkey namespace list
hkey namespace search   [<query>]
```

### secret

```
hkey secret create   --ref <ref> [--value <v>|--from-file <file>|--stdin]
                     [--label <k=v>...] [--description <desc>] [--type <type>]
hkey secret reveal   --ref <ref> [--as-hex|--as-base64]
hkey secret describe [--ref <ref>|--id <id>]
hkey secret update   --ref <ref> [--label <k=v>...] [--description <desc>]
hkey secret delete   --ref <ref>
hkey secret list     --namespace <ns>
hkey secret search   [<query>]
hkey secret revise   --ref <ref> [--value <v>|--from-file <file>|--stdin]
hkey secret annotate --ref <ref> [--label <k=v>...]
hkey secret activate --ref <ref>
```

Secret references use the format `/namespace:key/path` optionally followed by `@<revision>`.

### masterkey

```
hkey masterkey create        --name <name> --backend file|pkcs11 [...]
hkey masterkey status
hkey masterkey describe      --name <name>
hkey masterkey activate      --name <name>
hkey masterkey unlock        --name <name> [--insecure-passphrase <p>]
hkey masterkey lock          --name <name>
hkey masterkey delete        --name <name>
hkey masterkey pkcs11-tokens
```

### pat

```
hkey pat create    --description <desc> [--ttl <duration>]
hkey pat list
hkey pat revoke    --id <id>
```

### rbac

```
hkey rbac rule create   --rule "<spec>"
hkey rbac rule list
hkey rbac rule describe --id <id>
hkey rbac rule delete   --id <id>

hkey rbac role create   --name <name>
hkey rbac role update   --name <name> [--description <desc>]
hkey rbac role list
hkey rbac role describe --name <name>
hkey rbac role add      --name <name> --rule "<spec>"

hkey rbac bind     --name <account> --role <role>|--rule "<spec>"
hkey rbac unbind   --id <binding_id>
hkey rbac bindings [--account <name>] [--all]
hkey rbac explain  --account <name> --permission <perm>
                   [--secret <ref>|--namespace <path>] [--near-misses]
```

### mfa

```
hkey mfa enroll
hkey mfa confirm      --code <totp-code>
hkey mfa verify       --code <totp-code>
hkey mfa disable
hkey mfa backup-codes
```

### audit

```
hkey audit events   [<filters>]
hkey audit verify
```

Note: audit requires a Commercial license.

### license

```
hkey license status
hkey license set     --from-file <file>
hkey license remove
```

### Other

```
hkey status                 Show server status summary
hkey rekey kek              Rotate a KEK and optionally migrate DEKs
hkey rewrap kek             Rewrap a KEK under a new master key version
hkey rewrap dek             Rewrap DEKs under a new KEK
hkey template render        Render a template using secrets
hkey shell <bash|zsh|fish>  Generate shell completion scripts
```

---

## Output

By default commands print human-readable output. Pass `--json` to get raw JSON suitable for scripting.

Human-readable output uses a consistent format:
- Describe commands: `  {:<20} {}` (2-space indent, 20-char key field)
- List commands: table with headers
- Status fields: uppercase (e.g., `ACTIVE`)
- Dates: ISO 8601 (`YYYY-MM-DD`)

---

## HTTP Client

**File**: `hierarkey-cli/src/http.rs`

`ApiClient` wraps `reqwest::blocking::Client`. All requests set `Authorization: Bearer <token>` and `Content-Type: application/json`. TLS certificate verification can be disabled with `--self-signed` for development setups.
