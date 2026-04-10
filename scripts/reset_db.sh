#!/bin/sh

set -e

if [ ! -e "./hierarkey-config.toml" ]; then
    echo "Error: hierarkey-config.toml not found in current directory." >&2
    exit 1
fi

if [ ! -e "./target/release" ]; then
    echo "Error: target/release directory not found. Please build the project first." >&2
    exit 1
fi

export DATABASE_URL="postgresql://hierarkey:hierarkey@localhost/hierarkey"

cargo build --release --all

#HKEY=./target/release/hkey
HIERARKEY=./target/release/hierarkey
CONFIG="--config ./hierarkey-config.toml"

~/.cargo/bin/sqlx database drop -y -f
~/.cargo/bin/sqlx database create
$HIERARKEY update-migrations $CONFIG --yes

$HIERARKEY bootstrap-master-key $CONFIG --usage wrap_kek --provider passphrase --insecure-passphrase masterkeypassphrase
$HIERARKEY bootstrap-admin-account $CONFIG --name admin --insecure-password adminadminadmin --no-pwd-change
