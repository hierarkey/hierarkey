-- Type definitions -----------------------------------------------------------------------------------
-- Table definition -----------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS rbac_rules
(
    id           uuid PRIMARY KEY          DEFAULT gen_random_uuid(),
    short_id     text UNIQUE               DEFAULT random_short_id('rul_', 12),
    raw_spec     text,
    spec_version int              NOT NULL DEFAULT 1,
    effect       rbac_effect      NOT NULL,
    permission   text             NOT NULL,
    target_kind  rbac_target_kind NOT NULL,
    pattern_raw  text,
    condition    jsonb,
    metadata     jsonb,
    created_at   timestamptz      NOT NULL DEFAULT now(),
    created_by   uuid,
    updated_at   timestamptz,
    updated_by   uuid,

    CONSTRAINT rbac_rules_target_shape CHECK (
        (
            target_kind = 'all'
                AND pattern_raw IS NULL
            )
            OR
        (
            target_kind IN ('namespace', 'secret', 'account')
                AND pattern_raw IS NOT NULL
            )
        )
);

-- Constraints ----------------------------------------------------------------------------------------
-- Indexes and Foreign Keys ---------------------------------------------------------------------------

CREATE INDEX IF NOT EXISTS idx_rbac_rules_perm_kind
    ON rbac_rules (permission, target_kind);

CREATE INDEX IF NOT EXISTS idx_rbac_rules_kind_effect
    ON rbac_rules (target_kind, effect);

CREATE INDEX IF NOT EXISTS idx_rbac_rules_perm_kind
    ON rbac_rules (permission, target_kind);

CREATE INDEX IF NOT EXISTS idx_rbac_rules_kind_effect
    ON rbac_rules (target_kind, effect);

-- Population -----------------------------------------------------------------------------------------
