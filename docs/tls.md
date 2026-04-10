# TLS Configuration

Hierarkey supports both HTTP and HTTPS modes. For production use, TLS is **strongly recommended**.

#### Quick Start: Self-Signed Certificate (Development)

For local development or testing, generate a self-signed certificate:
```bash
# Create directory for certificates
mkdir -p ./data/server

# Generate EC private key (prime256v1 / secp256r1)
openssl ecparam -name prime256v1 -genkey -noout -out data/server/key.pem

# Generate self-signed certificate (valid for 365 days)
openssl req -new -x509 -key data/server/key.pem -out data/server/cert.pem -days 365 \
  -subj "/C=US/ST=California/L=San Francisco/O=MyOrg/CN=localhost"

# Set secure permissions (REQUIRED)
chmod 600 data/server/key.pem
chmod 644 data/server/cert.pem
```

**Important**: The server will **refuse to start** if `key.pem` does not have `0600` permissions (owner read/write only). This is a security check to prevent accidental exposure of private keys.

#### Production: Let's Encrypt Certificate

For production deployments, use a certificate from a trusted Certificate Authority like Let's Encrypt:
```bash
# Install certbot
sudo apt-get install certbot  # Debian/Ubuntu
# or
brew install certbot          # macOS

# Obtain certificate (requires port 80 access)
sudo certbot certonly --standalone -d hierarkey.example.com

# Certificates will be in:
# /etc/letsencrypt/live/hierarkey.example.com/fullchain.pem
# /etc/letsencrypt/live/hierarkey.example.com/privkey.pem

# Copy to hierarkey data directory
sudo cp /etc/letsencrypt/live/hierarkey.example.com/fullchain.pem data/server/cert.pem
sudo cp /etc/letsencrypt/live/hierarkey.example.com/privkey.pem data/server/key.pem
sudo chown $USER:$USER data/server/*.pem
chmod 600 data/server/key.pem
chmod 644 data/server/cert.pem
```

#### Production: Custom Certificate Authority

If you have your own CA certificate:
```bash
# Generate private key
openssl ecparam -name prime256v1 -genkey -noout -out data/server/key.pem

# Generate Certificate Signing Request (CSR)
openssl req -new -key data/server/key.pem -out data/cert.csr \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=hierarkey.example.com"

# Send cert.csr to your CA and receive signed certificate
# Save the signed certificate as data/server/cert.pem

# Set permissions
chmod 600 data/server/key.pem
chmod 644 data/server/cert.pem
```

#### Configuration

Edit `config.toml`:
```toml
[server]
# TLS mode (RECOMMENDED for production)
mode = "tls"
bind_address = "0.0.0.0:8443"  # Listen on all interfaces, port 8443
cert_path = "data/server/cert.pem"
key_path = "data/server/key.pem"

# HTTP mode (NOT recommended for production)
# mode = "http"
# bind_address = "127.0.0.1:8080"
# allow_insecure_http = true  # MUST be explicitly set to true
```

#### Configuration Options Explained

**`mode`**
- `"tls"` - Use HTTPS with TLS encryption (default, recommended)
- `"http"` - Use plain HTTP without encryption (requires `allow_insecure_http = true`)

**`bind_address`**
- `"127.0.0.1:8443"` - Listen only on localhost (local development)
- `"0.0.0.0:8443"` - Listen on all network interfaces (production)
- Port `8443` is conventional for HTTPS services (alternative to `443`)

**`cert_path` and `key_path`**
- Path to your TLS certificate and private key
- Can be absolute paths: `"/etc/hierarkey/cert.pem"`
- Or relative to working directory: `"data/server/cert.pem"`

**`allow_insecure_http`**
- Safety feature to prevent accidental HTTP use in production
- Must be explicitly set to `true` to use HTTP mode
- Default: `false`

#### Security Considerations

1. **Private Key Protection**
    - The server checks that `key.pem` has `0600` permissions
    - If permissions are too open (e.g., `0644`), the server will refuse to start
    - Never commit private keys to version control

2. **Certificate Validation**
    - Self-signed certificates will trigger browser warnings
    - For production, use certificates from a trusted CA
    - Clients can add self-signed certs to their trust store for development

3. **TLS Configuration**
    - hierarkey uses modern TLS 1.2+ with secure cipher suites
    - Old/insecure protocols (SSLv3, TLS 1.0) are disabled
    - Perfect Forward Secrecy (PFS) is enabled

#### Testing Your TLS Setup
```bash
# Start the server
hierarkey serve --config hierarkey-config.toml

# Test with curl (self-signed cert)
curl -k https://localhost:8443/healthz

# Test with curl (trusted cert)
curl https://hierarkey.example.com:8443/healthz

# Check certificate details
openssl s_client -connect localhost:8443 -showcerts

# Verify certificate chain
openssl verify -CAfile data/server/cert.pem data/server/cert.pem
```

#### Client Configuration

When using self-signed certificates, the `hkey` CLI does not support specifying a custom CA cert file directly. You have two options:

```bash
# Option 1: Pass --self-signed to skip certificate verification (INSECURE — dev only)
hkey --self-signed auth login --name admin
hkey --self-signed secret reveal --ref /prod:my-secret

# Option 2: Add the cert to the system trust store so hkey trusts it permanently

# Linux
sudo cp data/server/cert.pem /usr/local/share/ca-certificates/hierarkey.crt
sudo update-ca-certificates

# macOS
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain data/server/cert.pem
```

#### Troubleshooting

**Error: "TLS key file has insecure permissions"**
```bash
# Fix permissions
chmod 600 data/server/key.pem
```

**Error: "certificate signed by unknown authority"**
```bash
# Use --self-signed flag for development/testing
hkey --self-signed auth whoami

# For a permanent fix, add the cert to the system trust store (see "Client Configuration" above)
```

**Error: "bind: address already in use"**
```bash
# Check what's using the port
sudo lsof -i :8443
# Or change port in config.toml
bind_address = "127.0.0.1:9443"
```

#### HTTP Mode (Development Only)

For local development where TLS is not needed:
```toml
[server]
mode = "http"
bind_address = "127.0.0.1:8080"
allow_insecure_http = true  # Required safety flag
```

**WARNING**: Never use HTTP mode in production or over untrusted networks. Credentials and secrets will be transmitted in plaintext.