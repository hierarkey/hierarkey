-- Row-integrity signing key table.
--
-- A signing key is a 32-byte random key stored encrypted (AES-256-GCM) in the database,
-- wrapped by an active master key — exactly like a KEK.  It is used at the application
-- layer to compute and verify per-row HMAC-BLAKE3 signatures over security-critical rows
-- (accounts, RBAC rules, RBAC bindings).  Because the key material lives only in memory
-- after the master key is unlocked, an attacker with raw database write access cannot forge
-- a valid HMAC without also compromising the running server process.
--
-- Only one signing key may be active (deleted_at IS NULL) at any time.
-- The partial unique index below enforces this at the database level.

-- Table definition -----------------------------------------------------------------------------------

CREATE TABLE signing_keys
(
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    short_id     text        UNIQUE DEFAULT random_short_id('sk_', 12),

    -- Wrapping algorithm used to encrypt the key material (matches KEK convention)
    algorithm    text        NOT NULL DEFAULT 'AES-GCM-256',
    -- Encrypted key material: nonce (12) || ciphertext (32) || tag (16) = 60 bytes
    ciphertext   bytea       NOT NULL,
    -- Master key that wrapped this signing key
    masterkey_id uuid        NOT NULL,

    created_at   timestamptz NOT NULL DEFAULT now(),
    -- Non-NULL means this key has been rotated out and is no longer active
    deleted_at   timestamptz,

    CONSTRAINT signing_keys_masterkey_fk
        FOREIGN KEY (masterkey_id)
        REFERENCES masterkeys(id)
        ON DELETE RESTRICT
);

-- Constraints ----------------------------------------------------------------------------------------

-- Exactly one active signing key at a time.
-- The expression `(1)` is constant for every row where deleted_at IS NULL, so only one
-- such row can exist (UNIQUE on a constant = at most one row in the partial index).
CREATE UNIQUE INDEX signing_keys_one_active
    ON signing_keys ((1))
    WHERE deleted_at IS NULL;

-- Indexes and Foreign Keys ---------------------------------------------------------------------------

CREATE INDEX signing_keys_masterkey_idx ON signing_keys (masterkey_id);
