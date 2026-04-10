# App Integration

How to fetch secrets from Hierarkey inside a running application.

## Authentication strategies

| Strategy | When to use |
|----------|-------------|
| **PAT (Personal Access Token)** | Local development, simple scripts |
| **Ed25519 service account** | Production apps, CI/CD, Kubernetes |

This guide covers both. The API calls are identical — only the token acquisition differs.

---

## Setup: service account and RBAC

Create a dedicated service account for your app. Never use an admin account.

```bash
# Create the service account
hkey account create --name myapp-prod --type service --activate

# Create a role with the minimum required permissions and bind it
hkey rbac role create --name myapp-reader
hkey rbac role add --name myapp-reader --rule "allow secret:reveal to namespace /prod/myapp"
hkey rbac role add --name myapp-reader --rule "allow secret:describe to namespace /prod/myapp"
hkey rbac bind --name myapp-prod --role myapp-reader
```

---

## Auth strategy A — PAT (development)

Create a long-lived token for the service account:

```bash
hkey auth login --name admin
hkey pat create --description "myapp-prod dev token" --ttl 43200   # 30 days
# Save the printed token: hkat_...
```

Set it in your environment:

```bash
export HIERARKEY_SERVER=http://localhost:8080
export HIERARKEY_TOKEN=hkat_...
```

---

## Auth strategy B — Ed25519 (production)

Generate a key pair and register the public key when creating the service account:

```bash
openssl genpkey -algorithm ed25519 -out myapp-prod.priv.pem
openssl pkey -in myapp-prod.priv.pem -pubout -out myapp-prod.pub.pem

hkey account create --name myapp-prod --type service \
  --public-key-file myapp-prod.pub.pem --activate
```

Obtain a short-lived token at runtime:

```bash
hkey auth sa token \
  --method keysig \
  --name myapp-prod \
  --private-key myapp-prod.priv.pem \
  --print access-token
# prints: hkat_...  (valid for 60 minutes by default)
```

Store only the private key in your secrets manager (Kubernetes secret, environment variable, etc.). The private key is the only credential that needs protecting — no long-lived token to rotate.

---

## Python

Install the dependency:

```bash
pip install requests
```

### Minimal example

```python
import os
import requests

HIERARKEY_SERVER = os.environ["HIERARKEY_SERVER"]
HIERARKEY_TOKEN  = os.environ["HIERARKEY_TOKEN"]

def reveal_secret(ref: str) -> str:
    """Reveal a secret by its full reference, e.g. '/prod/myapp:db/password'."""
    resp = requests.post(
        f"{HIERARKEY_SERVER}/v1/secrets/reveal",
        json={"ref": ref},
        headers={"Authorization": f"Bearer {HIERARKEY_TOKEN}"},
        timeout=5,
    )
    resp.raise_for_status()
    return resp.json()["data"]["value"]


# Usage
db_password = reveal_secret("/prod/myapp:db/password")
api_key      = reveal_secret("/prod/myapp:api-key")
```

### Production example with startup caching

Fetch all secrets once at startup and keep them in memory. This avoids latency on every request and reduces load on Hierarkey.

```python
import os
import sys
import logging
import requests
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

@dataclass
class Secrets:
    db_password: str
    api_key: str

class HierakeyClient:
    def __init__(self, server: str, token: str):
        self.server = server
        self.session = requests.Session()
        self.session.headers["Authorization"] = f"Bearer {token}"

    def reveal(self, ref: str) -> str:
        resp = self.session.post(
            f"{self.server}/v1/secrets/reveal",
            json={"ref": ref},
            timeout=5,
        )
        resp.raise_for_status()
        return resp.json()["data"]["value"]


def load_secrets() -> Secrets:
    client = HierakeyClient(
        server=os.environ["HIERARKEY_SERVER"],
        token=os.environ["HIERARKEY_TOKEN"],
    )
    try:
        return Secrets(
            db_password=client.reveal("/prod/myapp:db/password"),
            api_key=client.reveal("/prod/myapp:api-key"),
        )
    except requests.exceptions.ConnectionError:
        logger.critical("Cannot reach Hierarkey server — aborting startup")
        sys.exit(1)
    except requests.exceptions.HTTPError as e:
        logger.critical("Failed to fetch secrets from Hierarkey: %s", e)
        sys.exit(1)


# At application startup:
secrets = load_secrets()

# Use throughout the app:
# db.connect(password=secrets.db_password)
# api_client = ApiClient(key=secrets.api_key)
```

---

## Go

### Minimal example

```go
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

type revealRequest struct {
	Ref string `json:"ref"`
}

type revealResponse struct {
	Data struct {
		Value string `json:"value"`
	} `json:"data"`
}

func revealSecret(server, token, ref string) (string, error) {
	body, _ := json.Marshal(revealRequest{Ref: ref})

	req, _ := http.NewRequest(http.MethodPost, server+"/v1/secrets/reveal", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("hierarkey: connection failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("hierarkey: HTTP %d: %s", resp.StatusCode, b)
	}

	var out revealResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("hierarkey: decode error: %w", err)
	}
	return out.Data.Value, nil
}

func main() {
	server := os.Getenv("HIERARKEY_SERVER")
	token  := os.Getenv("HIERARKEY_TOKEN")

	dbPassword, err := revealSecret(server, token, "/prod/myapp:db/password")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Println("Got DB password:", dbPassword[:4]+"****")
}
```

### Production example with startup caching

```go
package hierarkey

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Client struct {
	server string
	token  string
	http   *http.Client
}

func NewClient(server, token string) *Client {
	return &Client{
		server: server,
		token:  token,
		http:   &http.Client{Timeout: 5 * time.Second},
	}
}

func (c *Client) Reveal(ref string) (string, error) {
	body, _ := json.Marshal(map[string]string{"ref": ref})

	req, _ := http.NewRequest(http.MethodPost, c.server+"/v1/secrets/reveal", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("reveal %q: %w", ref, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("reveal %q: HTTP %d: %s", ref, resp.StatusCode, b)
	}

	var out struct {
		Data struct{ Value string } `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	return out.Data.Value, nil
}

// AppSecrets holds all secrets fetched at startup.
type AppSecrets struct {
	DBPassword string
	APIKey     string
}

// LoadSecrets fetches all required secrets. Call once at startup.
// Returns an error if any secret cannot be fetched — the caller should
// treat this as fatal and abort startup.
func LoadSecrets(server, token string) (*AppSecrets, error) {
	c := NewClient(server, token)

	dbPassword, err := c.Reveal("/prod/myapp:db/password")
	if err != nil {
		return nil, err
	}

	apiKey, err := c.Reveal("/prod/myapp:api-key")
	if err != nil {
		return nil, err
	}

	return &AppSecrets{
		DBPassword: dbPassword,
		APIKey:     apiKey,
	}, nil
}
```

In `main.go`:

```go
secrets, err := hierarkey.LoadSecrets(
    os.Getenv("HIERARKEY_SERVER"),
    os.Getenv("HIERARKEY_TOKEN"),
)
if err != nil {
    log.Fatalf("failed to load secrets: %v", err)
}
```

---

## Error handling guidance

| Error | Cause | Action |
|-------|-------|--------|
| Connection refused / timeout | Hierarkey unreachable | Abort startup; do not start with missing secrets |
| HTTP 401 | Token expired or invalid | Refresh token (Ed25519) or rotate PAT; abort if unrecoverable |
| HTTP 403 | Service account lacks permission | Fix RBAC; don't retry |
| HTTP 404 | Secret path wrong | Fix the reference in code; don't retry |
| HTTP 5xx | Hierarkey internal error | Retry with backoff; alert if persistent |

**Never start the application with default/empty secrets.** If Hierarkey is unreachable at startup, fail fast and let the orchestrator restart the pod/process once Hierarkey is available again.
