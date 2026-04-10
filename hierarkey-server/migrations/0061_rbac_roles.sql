-- Type definitions -----------------------------------------------------------------------------------
-- Table definition -----------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS rbac_roles
(
    id         uuid PRIMARY KEY     DEFAULT gen_random_uuid(),
    short_id   text UNIQUE          DEFAULT random_short_id('rol_', 12),
    name       text        NOT NULL UNIQUE,
    metadata   jsonb,
    is_system  boolean     NOT NULL DEFAULT false, -- built-in roles
    created_at timestamptz NOT NULL DEFAULT now(),
    created_by uuid,
    updated_at timestamptz,
    updated_by uuid
);

-- Constraints ----------------------------------------------------------------------------------------
-- Indexes and Foreign Keys ---------------------------------------------------------------------------
-- Population -----------------------------------------------------------------------------------------
