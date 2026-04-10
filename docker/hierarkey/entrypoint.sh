#!/bin/bash
set -euo pipefail

DATA_DIR="/data"
CONFIG_FILE="$DATA_DIR/config.toml"
INIT_FLAG="$DATA_DIR/.initialized"

POSTGRES_URL="${POSTGRES_URL:-postgres://hierarkey:hierarkey@postgres:5432/hierarkey}"
BIND_ADDRESS="${HIERARKEY_BIND_ADDRESS:-0.0.0.0:8080}"
ADMIN_USER="${HIERARKEY_ADMIN_USER:-admin}"
ADMIN_PASSWORD="${HIERARKEY_ADMIN_PASSWORD:-}"

mkdir -p "$DATA_DIR/master-keys"

# Generate config from environment (always regenerated so env changes take effect)
cat > "$CONFIG_FILE" << TOML
[logging]
level = "info"

[database]
url = "$POSTGRES_URL"

[database.tls]
enabled = false

[server]
mode = "http"
bind_address = "$BIND_ADDRESS"
allow_insecure_http = true

[masterkey]
default_backend = "file"
default_file_type = "insecure"
allow_insecure_masterkey = true

[masterkey.file]
enabled = true
allowed_types = ["insecure"]
path = "$DATA_DIR/master-keys"
file_mode = "0600"
dir_mode = "0700"
owner = "root"
group = "root"

[masterkey.pkcs11]
enabled = false
module = ""
token_label = ""
pin_source = ""
key_prefix = ""

[auth]
audience = "hierarkey-server"
allow_passphrase_auth = true
allow_ed25519_auth = true
allow_mtls_auth = false
access_token_ttl_seconds = 900
refresh_token_ttl_seconds = 604800
TOML

echo "==> Running database migrations..."
hierarkey update-migrations --config "$CONFIG_FILE" --yes

if [ ! -f "$INIT_FLAG" ]; then
    echo "==> First boot — initializing hierarkey..."

    echo "==> Bootstrapping master key..."
    if ! hierarkey bootstrap-master-key \
        --config "$CONFIG_FILE" \
        --usage wrap_kek \
        --provider insecure \
        --name "demo-root"; then
        echo "==> Master key already exists, skipping..."
    fi

    echo "==> Bootstrapping admin account..."
    if [ -z "$ADMIN_PASSWORD" ]; then
        set +o pipefail
        ADMIN_PASSWORD=$(tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 20)
        set -o pipefail
        SHOW_CREDS=1
    fi

    if hierarkey bootstrap-admin-account \
        --config "$CONFIG_FILE" \
        --name "$ADMIN_USER" \
        --insecure-password "$ADMIN_PASSWORD" \
        --no-pwd-change; then
        if [ "${SHOW_CREDS:-0}" = "1" ]; then
            echo ""
            echo "  ╔══════════════════════════════════════════════════╗"
            echo "  ║           HIERARKEY DEMO CREDENTIALS            ║"
            echo "  ║                                                  ║"
            printf  "  ║  Username : %-36s║\n" "$ADMIN_USER "
            printf  "  ║  Password : %-36s║\n" "$ADMIN_PASSWORD "
            echo "  ║                                                  ║"
            echo "  ║  Save these — they will not be shown again.     ║"
            echo "  ╚══════════════════════════════════════════════════╝"
            echo ""
        fi
    else
        echo "==> Admin account already exists, skipping..."
    fi

    touch "$INIT_FLAG"
fi

echo "==> Starting hierarkey server..."
exec hierarkey serve --config "$CONFIG_FILE"
