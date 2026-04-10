# Backup and Restore

Hierarkey state lives in two places: the PostgreSQL database and the master key file. Both must be backed up together for a full recovery to be possible.

---

## What to back up

| Component | Location | Contains | Required for recovery |
|-----------|----------|----------|----------------------|
| PostgreSQL database | DB server | All namespaces, secrets, accounts, RBAC, KEKs | Yes |
| Master key file | `/etc/hierarkey/master-keys/` | Encrypted master key | Yes |
| Master key passphrase | Password manager | Passphrase to derive the key | Yes |
| Config file | `/etc/hierarkey/config.toml` | Server configuration | Recommended |

> Without the master key file AND the passphrase, the encrypted KEKs in the database cannot be decrypted and all secret values are permanently inaccessible.

---

## 1. Database backup

### pg_dump (logical backup)

```bash
pg_dump \
  --host=db.internal \
  --username=hierarkey \
  --dbname=hierarkey \
  --format=custom \
  --file=/backups/hierarkey-$(date +%Y%m%d-%H%M%S).dump
```

The `--format=custom` flag produces a compressed binary dump that supports selective restore.

### Automate with cron

```cron
# /etc/cron.d/hierarkey-backup
0 2 * * * postgres pg_dump --host=localhost --username=hierarkey \
  --dbname=hierarkey --format=custom \
  --file=/backups/hierarkey-$(date +\%Y\%m\%d).dump
```

### Kubernetes CronJob

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: hierarkey-backup
  namespace: hierarkey
spec:
  schedule: "0 2 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: OnFailure
          containers:
            - name: pg-dump
              image: postgres:16
              command:
                - pg_dump
                - --host=$(DB_HOST)
                - --username=$(DB_USER)
                - --dbname=hierarkey
                - --format=custom
                - --file=/backups/hierarkey-$(date +%Y%m%d).dump
              env:
                - name: PGPASSWORD
                  valueFrom:
                    secretKeyRef:
                      name: hierarkey-db-secret
                      key: password
              volumeMounts:
                - name: backup-pvc
                  mountPath: /backups
          volumes:
            - name: backup-pvc
              persistentVolumeClaim:
                claimName: hierarkey-backup-pvc
```

---

## 2. Master key file backup

The master key file directory is small (a few KB). Back it up encrypted:

```bash
# Encrypt and upload to S3 (or any object store)
tar czf - /etc/hierarkey/master-keys/ \
  | gpg --symmetric --cipher-algo AES256 \
  | aws s3 cp - s3://my-backup-bucket/hierarkey/master-keys-$(date +%Y%m%d).tar.gz.gpg
```

Keep the GPG passphrase separate from the master key passphrase, and store both in a password manager.

---

## 3. Verify backups

A backup you have never restored is an assumption, not a backup. Test monthly:

```bash
# Restore the database dump to a test instance
pg_restore \
  --host=test-db.internal \
  --username=hierarkey \
  --dbname=hierarkey_test \
  --format=custom \
  hierarkey-20260101.dump

# Start a Hierarkey server pointing at the test database
# and verify you can reveal a known secret
hkey secret reveal /prod/myapp:db/password
```

---

## 4. Restore procedure

### Step 1 — Restore the database

```bash
# Create an empty database (if needed)
createdb --host=db.internal --username=postgres hierarkey

# Restore from dump
pg_restore \
  --host=db.internal \
  --username=hierarkey \
  --dbname=hierarkey \
  --format=custom \
  hierarkey-20260101.dump
```

If restoring to an existing database with existing tables, add `--clean --if-exists`:

```bash
pg_restore \
  --host=db.internal \
  --username=hierarkey \
  --dbname=hierarkey \
  --format=custom \
  --clean --if-exists \
  hierarkey-20260101.dump
```

### Step 2 — Restore the master key file

```bash
aws s3 cp s3://my-backup-bucket/hierarkey/master-keys-20260101.tar.gz.gpg - \
  | gpg --decrypt \
  | tar xzf - -C /
# File is restored to /etc/hierarkey/master-keys/
```

### Step 3 — Run migrations

Migrations are idempotent. Run them even if restoring a recent backup to ensure schema is current:

```bash
hierarkey update-migrations --config /etc/hierarkey/config.toml
```

### Step 4 — Start the server

```bash
HIERARKEY_MASTERKEY_PASSPHRASE="your-passphrase" \
  systemctl start hierarkey
```

### Step 5 — Verify

```bash
curl https://hierarkey.internal/healthz
# {"status":"ok"}

curl https://hierarkey.internal/readyz
# {"status":"ok"}

hkey auth whoami
hkey secret reveal /prod/myapp:db/password
```

---

## 5. Retention policy

| Backup type | Minimum retention |
|-------------|------------------|
| Daily database dump | 30 days |
| Weekly database dump | 90 days |
| Monthly database dump | 1 year |
| Master key file | Keep every version indefinitely (they are tiny) |

Keep at least one off-site copy of both the database dump and the master key file.

---

## 6. Point-in-time recovery (PITR)

For production deployments with strict RPO requirements, enable PostgreSQL WAL archiving for point-in-time recovery:

```bash
# postgresql.conf
wal_level = replica
archive_mode = on
archive_command = 'aws s3 cp %p s3://my-backup-bucket/wal/%f'
```

This allows restoring to any point in time, not just the last daily dump. See the [PostgreSQL PITR documentation](https://www.postgresql.org/docs/current/continuous-archiving.html) for full setup details.
