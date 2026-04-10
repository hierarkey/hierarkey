#!/bin/bash

set -e

CERT_DIR="./data/postgres/certs"
DAYS=3650

echo "Creating certificate directory..."
mkdir -p "$CERT_DIR"

if [ -e "$CERT_DIR/ca-cert.pem" ]; then
    echo "CA certificate already exists. Exiting to avoid overwriting existing certificates."
    exit 0
fi

CA_CONF="$CERT_DIR/ca.cnf"
SERVER_CONF="$CERT_DIR/server.cnf"
CLIENT_CONF="$CERT_DIR/client.cnf"

generate_ca() {
    local cn=$1
    local o=$2
    local c=$3

    echo "Generating CA private key..."
    openssl genrsa -out "$CERT_DIR/ca-key.pem" 4096

    echo "Writing CA config..."
    cat > "$CA_CONF" <<EOF
[ req ]
distinguished_name = dn
x509_extensions = v3_ca
prompt = no

[ dn ]
CN = $cn
O = $o
C = $c

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
EOF

    echo "Generating CA certificate (v3)..."
    openssl req -new -x509 -days $DAYS -key "$CERT_DIR/ca-key.pem" \
        -out "$CERT_DIR/ca-cert.pem" \
        -config "$CA_CONF" -sha256
}

generate_server_cert() {
    local cn=$1
    local o=$2
    local c=$3

    echo "Generating server private key..."
    openssl genrsa -out "$CERT_DIR/$cn-key.pem" 4096

    echo "Writing server config with SAN..."
    cat > "$SERVER_CONF" <<EOF
[ req ]
distinguished_name = dn
prompt = no

[ dn ]
CN = $cn
O = $o
C = $c

[ v3_req ]
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = $cn
DNS.2 = localhost
IP.1  = 127.0.0.1
EOF

    echo "Generating server CSR..."
    openssl req -new -key "$CERT_DIR/$cn-key.pem" \
        -out "$CERT_DIR/$cn-req.pem" \
        -config "$SERVER_CONF"

    echo "Signing server certificate (v3)..."
    openssl x509 -req -days $DAYS -in "$CERT_DIR/$cn-req.pem" \
        -CA "$CERT_DIR/ca-cert.pem" -CAkey "$CERT_DIR/ca-key.pem" \
        -CAcreateserial -out "$CERT_DIR/$cn-cert.pem" \
        -extfile "$SERVER_CONF" -extensions v3_req -sha256
}

generate_client_cert() {
    local cn=$1
    local o=$2
    local c=$3

    echo "Generating client private key..."
    openssl genrsa -out "$CERT_DIR/$cn-key.pem" 4096

    echo "Writing client config..."
    cat > "$CLIENT_CONF" <<EOF
[ req ]
distinguished_name = dn
prompt = no

[ dn ]
CN = $cn
O = $o
C = $c

[ v3_req ]
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF

    echo "Generating client CSR..."
    openssl req -new -key "$CERT_DIR/$cn-key.pem" \
        -out "$CERT_DIR/$cn-req.pem" \
        -config "$CLIENT_CONF"

    echo "Signing client certificate (v3)..."
    openssl x509 -req -days $DAYS -in "$CERT_DIR/$cn-req.pem" \
        -CA "$CERT_DIR/ca-cert.pem" -CAkey "$CERT_DIR/ca-key.pem" \
        -CAcreateserial -out "$CERT_DIR/$cn-cert.pem" \
        -extfile "$CLIENT_CONF" -extensions v3_req -sha256
}

generate_ca "PostgreSQL-CA" "hierarkey" "NL"
generate_server_cert "postgres" "hierarkey" "NL"
generate_client_cert "hierarkey" "hierarkey" "NL"

echo "Done. Generated:"
echo "  CA:      $CERT_DIR/ca-cert.pem"
echo "  Server:  $CERT_DIR/postgres-cert.pem"
echo "  Client:  $CERT_DIR/hierarkey-cert.pem"
