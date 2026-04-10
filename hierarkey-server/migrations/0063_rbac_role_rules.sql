-- Type definitions -----------------------------------------------------------------------------------
-- Table definition -----------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS rbac_role_rules
(
    role_id    uuid        NOT NULL REFERENCES rbac_roles (id) ON DELETE CASCADE,
    rule_id    uuid        NOT NULL REFERENCES rbac_rules (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    created_by uuid,
    PRIMARY KEY (role_id, rule_id)
);

-- Constraints ----------------------------------------------------------------------------------------
-- Indexes and Foreign Keys ---------------------------------------------------------------------------

CREATE INDEX IF NOT EXISTS idx_rbac_role_rules_role_id
    ON rbac_role_rules (role_id);

CREATE INDEX IF NOT EXISTS idx_rbac_role_rules_rule_id
    ON rbac_role_rules (rule_id);

-- Population -----------------------------------------------------------------------------------------
