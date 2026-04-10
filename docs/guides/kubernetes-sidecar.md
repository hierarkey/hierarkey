# Kubernetes Sidecar Pattern

Run a sidecar container alongside your application that keeps secrets fresh in a shared in-memory volume. The main container reads secrets as plain files without knowing anything about Hierarkey.

## Why sidecar over init container

| | Init container | Sidecar |
|---|---|---|
| Fetches secrets | Once, at pod start | Periodically |
| Picks up revisions | Only on pod restart | Automatically |
| Pod restart needed for rotation | Yes | No |
| Complexity | Low | Slightly higher |

Use a sidecar when secrets change frequently or when you want zero-downtime rotation without restarting pods.

---

## How it works

```
Pod
├── sidecar (jaytaph/hierarkey:latest)
│   └── runs hkey in a loop
│       └── writes to /run/secrets/ (shared tmpfs volume)
│
└── app container
    └── reads /run/secrets/db-password
        └── reads /run/secrets/api-key
```

The sidecar fetches all secrets every N minutes and writes them to files. The app reads the files at startup and re-reads them before use (or on a signal). The volume is `emptyDir: { medium: Memory }` — contents never touch disk.

---

## 1. Set up the service account in Hierarkey

```bash
# Create the service account
hkey account create --name k8s-myapp --type service --activate

# Create a narrow RBAC role and bind it
hkey rbac role create --name k8s-myapp-reader
hkey rbac role add --name k8s-myapp-reader --rule "allow secret:reveal to namespace /prod/myapp"
hkey rbac bind --name k8s-myapp --role k8s-myapp-reader
```

Create a long-lived PAT for the service account:

```bash
hkey auth login --name admin
# Switch to acting on behalf of the service account isn't needed —
# create the PAT as admin and target the service account
hkey pat create --description "k8s-myapp sidecar token" --ttl 525600  # 1 year
# Save the token: hkat_...
```

> For production, prefer Ed25519 authentication so you have no long-lived token to manage. See [App Integration](app-integration.md) for how to set that up, and adapt the sidecar script below to call `hkey auth sa token` before each fetch cycle.

---

## 2. Store the token as a Kubernetes Secret

```bash
kubectl -n myapp create secret generic hierarkey-token \
  --from-literal=token=hkat_...
```

Or as a manifest (base64-encode the token first):

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: hierarkey-token
  namespace: myapp
type: Opaque
stringData:
  token: "hkat_..."   # stringData handles encoding for you
```

---

## 3. The sidecar script

The sidecar uses a simple shell loop. Mount this as a ConfigMap or bake it into a custom image based on `jaytaph/hierarkey:latest`.

```bash
#!/bin/sh
# /scripts/fetch-secrets.sh
set -e

REFRESH_INTERVAL="${HIERARKEY_REFRESH_INTERVAL:-300}"   # seconds, default 5 min
SECRETS_DIR="/run/secrets"

mkdir -p "$SECRETS_DIR"

fetch() {
  echo "[hierarkey-sidecar] Fetching secrets..."
  hkey secret reveal /prod/myapp:db/password    > "$SECRETS_DIR/db-password.tmp"
  hkey secret reveal /prod/myapp:api-key        > "$SECRETS_DIR/api-key.tmp"

  # Atomic rename so the app never reads a partially written file
  mv "$SECRETS_DIR/db-password.tmp" "$SECRETS_DIR/db-password"
  mv "$SECRETS_DIR/api-key.tmp"     "$SECRETS_DIR/api-key"

  echo "[hierarkey-sidecar] Done. Next refresh in ${REFRESH_INTERVAL}s."
}

# Fetch immediately on startup, then loop
fetch
while true; do
  sleep "$REFRESH_INTERVAL"
  fetch
done
```

---

## 4. Full Deployment manifest

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
  namespace: myapp
spec:
  replicas: 2
  selector:
    matchLabels:
      app: myapp
  template:
    metadata:
      labels:
        app: myapp
    spec:
      volumes:
        # In-memory volume — contents never written to disk
        - name: secrets-vol
          emptyDir:
            medium: Memory
        # The sidecar script (see step 3)
        - name: sidecar-scripts
          configMap:
            name: hierarkey-sidecar-scripts
            defaultMode: 0755

      containers:
        # ── Main application ─────────────────────────────────────────
        - name: myapp
          image: your-registry/myapp:latest
          volumeMounts:
            - name: secrets-vol
              mountPath: /run/secrets
              readOnly: true
          env:
            - name: DB_PASSWORD_FILE
              value: /run/secrets/db-password
            - name: API_KEY_FILE
              value: /run/secrets/api-key
          # Give the sidecar a few seconds to write secrets before
          # the app starts reading them
          startupProbe:
            exec:
              command: ["test", "-f", "/run/secrets/db-password"]
            initialDelaySeconds: 5
            periodSeconds: 2
            failureThreshold: 15

        # ── Hierarkey sidecar ─────────────────────────────────────────
        - name: hierarkey-sidecar
          image: jaytaph/hierarkey:latest
          command: ["/scripts/fetch-secrets.sh"]
          volumeMounts:
            - name: secrets-vol
              mountPath: /run/secrets
            - name: sidecar-scripts
              mountPath: /scripts
          env:
            - name: HKEY_SERVER_URL
              value: "https://hierarkey.internal"
            - name: HKEY_TOKEN
              valueFrom:
                secretKeyRef:
                  name: hierarkey-token
                  key: token
            - name: HIERARKEY_REFRESH_INTERVAL
              value: "300"
          resources:
            requests:
              cpu: 10m
              memory: 32Mi
            limits:
              cpu: 100m
              memory: 64Mi
```

---

## 5. ConfigMap for the sidecar script

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: hierarkey-sidecar-scripts
  namespace: myapp
data:
  fetch-secrets.sh: |
    #!/bin/sh
    set -e
    REFRESH_INTERVAL="${HIERARKEY_REFRESH_INTERVAL:-300}"
    SECRETS_DIR="/run/secrets"
    mkdir -p "$SECRETS_DIR"

    fetch() {
      echo "[hierarkey-sidecar] Fetching secrets..."
      hkey secret reveal /prod/myapp:db/password > "$SECRETS_DIR/db-password.tmp"
      hkey secret reveal /prod/myapp:api-key     > "$SECRETS_DIR/api-key.tmp"
      mv "$SECRETS_DIR/db-password.tmp" "$SECRETS_DIR/db-password"
      mv "$SECRETS_DIR/api-key.tmp"     "$SECRETS_DIR/api-key"
      echo "[hierarkey-sidecar] Done."
    }

    fetch
    while true; do
      sleep "$REFRESH_INTERVAL"
      fetch
    done
```

---

## 6. Reading secrets in your app

Read secrets from files rather than environment variables. Files can be updated by the sidecar without a pod restart; environment variables cannot.

**Python:**
```python
def read_secret(name: str) -> str:
    with open(f"/run/secrets/{name}") as f:
        return f.read().strip()

db_password = read_secret("db-password")
```

**Go:**
```go
func readSecret(name string) (string, error) {
    b, err := os.ReadFile("/run/secrets/" + name)
    if err != nil {
        return "", err
    }
    return strings.TrimSpace(string(b)), nil
}
```

If you want to pick up rotated secrets without a pod restart, re-read the file on each use (or on a configurable interval) rather than caching at startup.

---

## 7. Verify it works

```bash
# Check the sidecar is running
kubectl -n myapp logs deployment/myapp -c hierarkey-sidecar

# Check secrets were written to the shared volume
kubectl -n myapp exec deployment/myapp -c myapp -- ls /run/secrets/
kubectl -n myapp exec deployment/myapp -c myapp -- cat /run/secrets/db-password
```
