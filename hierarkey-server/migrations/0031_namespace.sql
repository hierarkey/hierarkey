-- Type definitions -----------------------------------------------------------------------------------
-- Table definition -----------------------------------------------------------------------------------

CREATE TABLE namespaces
(
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    short_id              text UNIQUE DEFAULT random_short_id('ns_', 12),

    namespace   text NOT NULL,
    status      text NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'disabled', 'destroyed')),
    metadata    jsonb       DEFAULT '{}'::jsonb,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz,
    deleted_at  timestamptz
);

-- Constraints ----------------------------------------------------------------------------------------
-- Indexes and Foreign Keys ---------------------------------------------------------------------------

CREATE UNIQUE INDEX namespaces_namespace_active_uniq
    ON namespaces (namespace)
    WHERE status <> 'destroyed';

CREATE INDEX namespaces_namespace_idx
    ON namespaces (namespace);

CREATE INDEX namespaces_metadata_gin_idx
    ON namespaces USING gin (metadata);

-- Population -----------------------------------------------------------------------------------------