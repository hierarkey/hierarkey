-- Type definitions -----------------------------------------------------------------------------------

CREATE TYPE masterkey_usage AS ENUM ('wrap_kek');
CREATE TYPE masterkey_status  AS ENUM ('active', 'disabled', 'retired');
CREATE TYPE masterkey_backend AS ENUM ('file', 'pkcs11');
CREATE TYPE masterkey_file_type AS ENUM ('passphrase', 'insecure');

-- Table definition -----------------------------------------------------------------------------------

CREATE TABLE masterkeys (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    short_id              text UNIQUE DEFAULT random_short_id('mk_', 12),
    name               text NOT NULL,

    usage              masterkey_usage NOT NULL,
    status             masterkey_status NOT NULL DEFAULT 'active',

    backend            masterkey_backend NOT NULL,
    file_type          masterkey_file_type,
    file_path          text,
    file_sha256        text,
    pkcs11_ref         jsonb NOT NULL DEFAULT '{}'::jsonb,

    metadata           jsonb NOT NULL DEFAULT '{}'::jsonb,

    created_at         timestamptz NOT NULL DEFAULT now(),
    created_by         uuid REFERENCES accounts(id) ON DELETE SET NULL,
    updated_at         timestamptz NOT NULL DEFAULT now(),
    updated_by         uuid REFERENCES accounts(id) ON DELETE SET NULL,
    retired_at         timestamptz,
    retired_by         uuid REFERENCES accounts(id) ON DELETE SET NULL
);

-- Constraints ----------------------------------------------------------------------------------------

ALTER TABLE masterkeys ADD CONSTRAINT masterkeys_backend_consistency CHECK (
    (backend = 'file' AND file_type IS NOT NULL AND file_path IS NOT NULL)
        OR
    (backend = 'pkcs11' AND file_type IS NULL AND file_path IS NULL)
    );

ALTER TABLE masterkeys ADD CONSTRAINT masterkeys_retire_consistency CHECK (
    (status <> 'retired' AND retired_at IS NULL AND retired_by IS NULL)
        OR
    (status = 'retired' AND retired_at IS NOT NULL)
    );

ALTER TABLE masterkeys ADD CONSTRAINT masterkeys_file_sha256_format CHECK (
    file_sha256 IS NULL OR file_sha256 ~ '^[0-9a-f]{64}$'
    );

-- Indexes and Foreign Keys ---------------------------------------------------------------------------

CREATE INDEX masterkeys_usage_idx ON masterkeys(usage);
CREATE INDEX masterkeys_usage_status_idx ON masterkeys(usage, status);

-- Only one active per usage
CREATE UNIQUE INDEX masterkeys_one_active_per_usage
    ON masterkeys (usage)
    WHERE status = 'active';
