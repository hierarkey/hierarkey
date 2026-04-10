# Master Key Management

The master key is the root of Hierarkey's encryption hierarchy. Every secret is encrypted with a Data-Encryption Key (DEK), which is encrypted with a Key-Encryption Key (KEK), which is encrypted with the master key. This guide covers day-2 operations: changing passphrases, checking status, and planning for disasters.

---

## How the master key works

```
Master key (derived from passphrase or stored in file)
  └─ encrypts KEK (one per namespace)
       └─ encrypts DEK (one per secret revision)
            └─ encrypts secret value
```

The master key never touches the database. KEKs are stored encrypted in the database. DEKs are generated fresh for each secret revision.

---

## 1. Check master key status

```bash
hkey masterkey status
```

Output shows each master key ID and whether it is locked or unlocked. Keys are unlocked at startup when the passphrase is supplied; they lock automatically if the server restarts without the passphrase.

```bash
hkey masterkey describe --name <name>
# or by short ID:
hkey masterkey describe --id mk_...
```

Shows the backend type, creation date, and who last locked/unlocked it.

---

## 2. Lock and unlock manually

```bash
# Lock (removes the in-memory key — secrets cannot be decrypted until unlocked)
hkey masterkey lock <id>

# Unlock (requires the passphrase)
hkey masterkey unlock <id>
```

You generally do not need to lock/unlock manually — the server handles this at startup. Manual locking is useful for maintenance windows or incident response.

---

## 3. Change the passphrase

Changing the passphrase on an existing master key is not supported as a direct command. The recommended approach is to rotate to a new master key (see section 4 below) with a new passphrase. This rewraps all KEKs onto the new key and retires the old one.

After the rotation, update the passphrase in your deployment environment and any backups.

---

## 4. Rotate to a new master key

Rotating means creating a new master key and re-encrypting all KEKs with it. Use this when:

- The old master key passphrase may be compromised.
- You are migrating backend types (e.g. file -> HSM).
- Your security policy requires periodic rotation.

```bash
# 1. Create the new master key
hkey masterkey create --name new-primary --usage wrap_kek --provider passphrase --generate-passphrase

# 2. Activate it (the previous active key moves to "draining" state)
hkey masterkey activate --name new-primary

# 3. Rewrap all KEKs from the old key to the new active one
#    Run repeatedly until the output says the old key is retired
hkey rewrap kek --from <old-key-name>

# 4. Verify all namespaces are accessible
hkey namespace list
hkey secret reveal /prod/myapp:db/password   # spot-check
```

> Rewrapping is online — it runs while the server is live. No secrets are unavailable during this time. The old key is retired automatically once all KEKs have been rewrapped off it.

---

## 5. Backup strategy

**Back up both the master key file AND the passphrase, but separately.**

| What | Where | How often |
|------|-------|-----------|
| Master key file directory (`/etc/hierarkey/master-keys/`) | Encrypted off-site backup | On every change (after rekey/repassphrase) |
| Master key passphrase | Password manager (separate from server) | After every change |
| PostgreSQL database | Standard backup (see [Backup and Restore](backup-and-restore.md)) | Daily minimum |

Without the master key file AND the passphrase, encrypted KEKs in the database cannot be decrypted. Keep them in separate locations so that a breach of one does not compromise the other.

---

## 6. Disaster recovery scenarios

### Scenario A — Server lost, database intact, master key backed up

1. Provision a new server.
2. Install Hierarkey.
3. Restore the master key file to `/etc/hierarkey/master-keys/`.
4. Apply the passphrase to the new instance.
5. Run migrations (`hierarkey update-migrations`) — they are idempotent.
6. Start the server. The existing KEKs and DEKs in the database will decrypt normally.

### Scenario B — Master key file lost, passphrase known

If you backed up only the database and not the master key file, recovery is not possible without the key file. The passphrase alone is insufficient — it derives the key, but the key is required to decrypt the stored KEKs.

**This is why backing up the master key file is critical.**

### Scenario C — Passphrase forgotten, key file intact

The key file encrypted with a passphrase cannot be opened without the passphrase. There is no recovery path.

If you suspect the passphrase is lost, rotate immediately while the server is still running (see step 4 above) to create a new key with a known passphrase before the server stops.

### Scenario D — Both master key and database backup available

Standard restore: bring up a new server, restore the database, restore the master key file, start with the passphrase. See [Backup and Restore](backup-and-restore.md) for the full procedure.

---

## 7. HSM / PKCS#11 (Commercial Edition)

Hierarkey's master key backend is pluggable. File-based (passphrase or insecure) backends are included in the community edition. HSM / PKCS#11 support is available in the [Hierarkey Commercial Edition](https://hierarkey.com/commercial). Cloud KMS backends (AWS KMS, GCP CKMS, HashiCorp Vault) are planned for a future release.
