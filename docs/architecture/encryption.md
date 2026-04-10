# Encryption Architecture

## Key Hierarchy

```
MasterKey  (file or PKCS#11 — one active at a time)
    │
    │  AES-256-GCM wrap
    ▼
KEK  (one per namespace, stored encrypted in DB)
    │
    │  AES-256-GCM wrap
    ▼
DEK  (one per secret revision, stored encrypted inline)
    │
    │  AES-256-GCM encryption
    ▼
Secret value  (plaintext, up to 2 MiB)
```

Each layer uses AES-256-GCM with a fresh 12-byte random nonce per operation.

---

## Master Key

The master key is the root of trust. Its raw bytes exist only in memory (while unlocked) or in a provider-specific protected store.

### Providers

**Passphrase (`File/Passphrase`)**

The master key is stored in a file, encrypted with a user-supplied passphrase.

- KDF: Argon2id
- Default parameters: 128 MiB memory, 3 iterations, 1 parallelism (configurable in `hierarkey-config.toml`)
- Format: `encrypted_key_bytes || nonce || salt || KDF_params` — all serialised to JSON on disk

**Insecure (`File/Insecure`)**

The master key is stored in plaintext in a file. Intended for local development only.

**PKCS#11 (`Pkcs11`)**

The master key lives inside a Hardware Security Module. The raw key bytes never leave the HSM. Hierarkey wraps/unwraps KEKs by calling the HSM via the PKCS#11 interface, supplying a PIN at unlock time.

### Lock / Unlock

All loaded master keys start **locked** in the in-memory keyring (`MasterKeyKeyring`). Unlocking requires providing the passphrase (or HSM PIN) via the API. Once unlocked, the crypto handle is held in memory until explicitly locked or the process restarts.

---

## KEK (Key Encryption Key)

A 32-byte AES key, encrypted by the master key and stored in the `keks` table.

**Encryption**: `AES-256-GCM(master_key, kek_bytes, aad)`

AAD (Additional Authenticated Data) binds the ciphertext to its context:
```
"hierarkey:kek-wrap:v1|<algo>|<masterkey_id>|<namespace_id>"
```

**In memory**: Decrypted KEKs are cached in `KekCache` (bounded to 1000 entries). The cache value is `Zeroizing<[u8; 32]>` — zeroed when evicted or the process exits.

**Rotation**: Creating a new KEK for a namespace (`POST /namespaces/{ns}/rotate-kek`) generates a fresh 32-byte key, encrypts it with the active master key, stores it, and creates a new `KekAssignment` revision pointing to it. Old DEKs continue to be decryptable via their stored `kek_id`.

**Rewrap**: When migrating KEKs from one master key to another (`POST /masterkeys/{id}/rewrap-keks`), each KEK is decrypted with the old master key and re-encrypted with the new one. The `masterkey_id` column is updated.

---

## DEK (Data Encryption Key)

A 32-byte AES key generated fresh for every new secret revision.

**Encryption of DEK**: `AES-256-GCM(kek, dek_bytes)`

Stored inline in `secret_revisions.encrypted_dek`:
```
nonce (12 bytes) || encrypted_dek (32 bytes) || GCM tag (16 bytes)  =  60 bytes total
```

**In memory**: `Zeroizing<[u8; 32]>` — zeroed on drop, never cached.

---

## Secret Value

Encrypted with the DEK at write time, decrypted at reveal time.

**Encryption**: `AES-256-GCM(dek, plaintext_bytes)`

Stored in `secret_revisions.encrypted_secret` as:
```
nonce (12 bytes) || ciphertext (variable) || GCM tag (16 bytes)
```

Maximum plaintext size: 2 MiB (`MAX_SECRET_SIZE` in `hierarkey-core/src/lib.rs`).

---

## Secret Reveal — Full Decryption Path

1. Load `SecretRevision` row (contains `encrypted_dek`, `encrypted_secret`, `kek_id`)
2. Look up KEK from cache or decrypt from DB using the active master key
3. Decrypt `encrypted_dek` with KEK → raw DEK bytes
4. Decrypt `encrypted_secret` with DEK → plaintext
5. Return plaintext; DEK zeroed on drop

---

## Re-wrapping DEKs

When namespace KEK is rotated, existing secret revisions still reference the old KEK. `POST /namespaces/{ns}/rewrap-deks` iterates all revisions under the namespace:

1. Decrypt each DEK with the old KEK
2. Re-encrypt each DEK with the new KEK
3. Update `secret_revisions.encrypted_dek` and `kek_id`

This is done in a single database transaction per batch.

---

## Key Sizes and Algorithm Summary

| Material | Size | Algorithm | Storage |
|----------|------|-----------|---------|
| Master key | provider-specific | — | File / HSM |
| KEK | 32 bytes | AES-256-GCM wrap | `keks.ciphertext` |
| DEK | 32 bytes | AES-256-GCM wrap | `secret_revisions.encrypted_dek` |
| Secret value | ≤ 2 MiB | AES-256-GCM | `secret_revisions.encrypted_secret` |
| Nonce | 12 bytes | Random per operation | Prepended to ciphertext |
| GCM tag | 16 bytes | — | Appended to ciphertext |

---

## Memory Safety

All cryptographic key material uses the `zeroize` crate:

- `Kek` wraps `Zeroizing<[u8; 32]>`
- `Dek` wraps `Zeroizing<[u8; 32]>`
- `Password` implements `Zeroize` and `ZeroizeOnDrop`

This ensures key bytes are overwritten when the values go out of scope, even in the presence of stack unwinding.
