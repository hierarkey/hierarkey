-- Type definitions -----------------------------------------------------------------------------------
-- Table definition -----------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS rbac_account_rules
(
    account_id  uuid        NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    rule_id     uuid        NOT NULL REFERENCES rbac_rules (id) ON DELETE CASCADE,

    valid_from  timestamptz,
    valid_until timestamptz,

    created_at  timestamptz NOT NULL DEFAULT now(),
    created_by  uuid,

    PRIMARY KEY (account_id, rule_id),

    CONSTRAINT rbac_account_rules_valid_range CHECK (
        valid_from IS NULL OR valid_until IS NULL OR valid_from <= valid_until
        )
);

-- Constraints ----------------------------------------------------------------------------------------
-- Indexes and Foreign Keys ---------------------------------------------------------------------------

CREATE INDEX IF NOT EXISTS idx_rbac_account_rules_account_id
    ON rbac_account_rules (account_id);

CREATE INDEX IF NOT EXISTS idx_rbac_account_rules_rule_id
    ON rbac_account_rules (rule_id);

CREATE INDEX IF NOT EXISTS idx_rbac_account_rules_validity
    ON rbac_account_rules (account_id, valid_until);

-- Population -----------------------------------------------------------------------------------------
