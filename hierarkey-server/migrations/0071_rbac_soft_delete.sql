-- Soft-delete support for RBAC entities and label-bind tables ----------------------------------------

-- rbac_roles: add deleted_at / deleted_by ---------------------------------------------------------
ALTER TABLE rbac_roles
    ADD COLUMN IF NOT EXISTS deleted_at timestamptz,
    ADD COLUMN IF NOT EXISTS deleted_by uuid;

-- Replace the unconditional UNIQUE constraint on name with a partial index
-- so that soft-deleted roles do not block name reuse.
ALTER TABLE rbac_roles DROP CONSTRAINT IF EXISTS rbac_roles_name_key;
CREATE UNIQUE INDEX IF NOT EXISTS rbac_roles_name_active
    ON rbac_roles (name) WHERE deleted_at IS NULL;

-- rbac_rules: add deleted_at / deleted_by ---------------------------------------------------------
ALTER TABLE rbac_rules
    ADD COLUMN IF NOT EXISTS deleted_at timestamptz,
    ADD COLUMN IF NOT EXISTS deleted_by uuid;

-- rbac_role_rules: add removed_at / removed_by ----------------------------------------------------
-- The primary key (role_id, rule_id) is kept; re-adding a removed rule UPDATEs the row
-- instead of INSERTing, so this column pair tracks the last removal only.
ALTER TABLE rbac_role_rules
    ADD COLUMN IF NOT EXISTS removed_at timestamptz,
    ADD COLUMN IF NOT EXISTS removed_by uuid;

-- Label bind tables -------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS rbac_label_rules (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id     uuid        NOT NULL REFERENCES rbac_rules (id) ON DELETE CASCADE,
    label_key   text        NOT NULL,
    label_value text        NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    created_by  uuid,
    UNIQUE (rule_id, label_key, label_value)
);

CREATE INDEX IF NOT EXISTS idx_rbac_label_rules_rule_id
    ON rbac_label_rules (rule_id);

CREATE INDEX IF NOT EXISTS idx_rbac_label_rules_label
    ON rbac_label_rules (label_key, label_value);

CREATE TABLE IF NOT EXISTS rbac_label_roles (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    role_id     uuid        NOT NULL REFERENCES rbac_roles (id) ON DELETE CASCADE,
    label_key   text        NOT NULL,
    label_value text        NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    created_by  uuid,
    UNIQUE (role_id, label_key, label_value)
);

CREATE INDEX IF NOT EXISTS idx_rbac_label_roles_role_id
    ON rbac_label_roles (role_id);

CREATE INDEX IF NOT EXISTS idx_rbac_label_roles_label
    ON rbac_label_roles (label_key, label_value);
