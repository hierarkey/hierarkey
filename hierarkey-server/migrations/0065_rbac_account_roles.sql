-- Type definitions -----------------------------------------------------------------------------------
-- Table definition -----------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS rbac_account_roles
(
    account_id  uuid        NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    role_id     uuid        NOT NULL REFERENCES rbac_roles (id) ON DELETE CASCADE,

    valid_from  timestamptz,
    valid_until timestamptz,

    created_at  timestamptz NOT NULL DEFAULT now(),
    created_by  uuid,

    PRIMARY KEY (account_id, role_id),

    CONSTRAINT rbac_account_roles_valid_range CHECK (
        valid_from IS NULL OR valid_until IS NULL OR valid_from <= valid_until
        )
);

-- Constraints ----------------------------------------------------------------------------------------
-- Indexes and Foreign Keys ---------------------------------------------------------------------------

CREATE INDEX IF NOT EXISTS idx_rbac_account_roles_account_id
    ON rbac_account_roles (account_id);

CREATE INDEX IF NOT EXISTS idx_rbac_account_roles_role_id
    ON rbac_account_roles (role_id);

CREATE INDEX IF NOT EXISTS idx_rbac_account_roles_validity
    ON rbac_account_roles (account_id, valid_until);

-- Population -----------------------------------------------------------------------------------------


