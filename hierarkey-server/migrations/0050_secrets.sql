-- Type definitions -----------------------------------------------------------------------------------
-- Table definition -----------------------------------------------------------------------------------

CREATE TABLE secrets
(
    id              uuid PRIMARY KEY     DEFAULT gen_random_uuid(),
    short_id        text UNIQUE          DEFAULT random_short_id('sec_', 12),

    namespace_id    uuid        NOT NULL REFERENCES namespaces (id),
    ref_ns          text        NOT NULL,
    ref_key         text        NOT NULL,
    status          text        NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'disabled', 'destroyed')),
    active_revision integer     NOT NULL DEFAULT 1 CHECK (active_revision >= 1),
    latest_revision integer     NOT NULL DEFAULT 1 CHECK (latest_revision >= 1),
    metadata        jsonb       NOT NULL DEFAULT '{}'::jsonb,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz,
    deleted_at      timestamptz
);

-- Constraints ----------------------------------------------------------------------------------------

ALTER TABLE secrets
    ADD CONSTRAINT secrets_namespace_ref_unique UNIQUE (namespace_id, ref_key);

-- Indexes and Foreign Keys ---------------------------------------------------------------------------

CREATE INDEX secrets_namespace_status_ref_idx
    ON secrets (namespace_id, status, ref_key);

CREATE INDEX secrets_namespace_ref_active_only_idx
    ON secrets (namespace_id, ref_key)
    WHERE status = 'active';

CREATE INDEX secrets_status_idx
    ON secrets (status);

CREATE INDEX secrets_metadata_gin_idx
    ON secrets USING gin (metadata jsonb_path_ops);

CREATE INDEX idx_secrets_metadata_labels ON secrets USING GIN ((metadata->'labels'));

CREATE INDEX idx_secrets_active ON secrets (ref_ns, ref_key)
    WHERE deleted_at IS NULL;

CREATE INDEX idx_secrets_updated ON secrets (updated_at)
    WHERE deleted_at IS NULL;

-- Population -----------------------------------------------------------------------------------------

