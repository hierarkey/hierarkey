#!/bin/bash

set -e


# If TLS is not enabled, start normally
if [ "$HIERARKEY_POSTGRES_TLS" != "1" ]; then
  echo "HIERARKEY_POSTGRES_TLS is not set. Starting Postgres without TLS."
  exec docker-entrypoint.sh postgres
  exit 0
fi



echo "Starting Postgres with TLS enabled..."

# Validate certificate directory and files exist
CERT_SOURCE_DIR="/data/postgres/certs"
CERT_TARGET_DIR="/var/lib/postgresql/certs"

if [ ! -d "$CERT_SOURCE_DIR" ]; then
  echo "*****************************************"
  echo "ERROR: Certificate directory $CERT_SOURCE_DIR does not exist."
  echo "*****************************************"
  exit 1
fi

REQUIRED_CERTS=("postgres-cert.pem" "postgres-key.pem" "ca-cert.pem")
for cert in "${REQUIRED_CERTS[@]}"; do
  if [ ! -f "$CERT_SOURCE_DIR/$cert" ]; then
    echo "*****************************************"
    echo "ERROR: Required certificate file missing: $cert"
    echo "Required files: ${REQUIRED_CERTS[*]}"
    echo "*****************************************"
    exit 1
  fi
done

# Create target directory if it doesn't exist
mkdir -p "$CERT_TARGET_DIR"

# Copy certificates
echo "Copying certificates to $CERT_TARGET_DIR..."
cp "$CERT_SOURCE_DIR"/*.pem "$CERT_TARGET_DIR/"

# Set proper permissions (key file must be 0600, others can be 0644)
chmod 0600 "$CERT_TARGET_DIR/postgres-key.pem"
chmod 0644 "$CERT_TARGET_DIR/postgres-cert.pem"
chmod 0644 "$CERT_TARGET_DIR/ca-cert.pem"
chown -R postgres:postgres "$CERT_TARGET_DIR"

# Start PostgreSQL with TLS enabled
echo "Starting PostgreSQL with TLS..."
exec docker-entrypoint.sh postgres \
  -c ssl=on \
  -c ssl_cert_file="$CERT_TARGET_DIR/postgres-cert.pem" \
  -c ssl_key_file="$CERT_TARGET_DIR/postgres-key.pem" \
  -c ssl_ca_file="$CERT_TARGET_DIR/ca-cert.pem" \
  -c hba_file="/etc/postgresql/pg_hba.conf"
