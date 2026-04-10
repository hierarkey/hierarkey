-- Type definitions -----------------------------------------------------------------------------------

CREATE TYPE account_type AS ENUM ('user', 'service', 'system');
CREATE TYPE account_status AS ENUM ('active', 'locked', 'disabled');

-- Table definition -----------------------------------------------------------------------------------

CREATE TABLE accounts
(
    id                    uuid                    DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
    short_id              text UNIQUE             DEFAULT random_short_id('acc_', 12),
    name                  text           NOT NULL,
    account_type          account_type   NOT NULL DEFAULT 'user',

    status                account_status NOT NULL DEFAULT 'active',
    status_reason         text,
    status_changed_at     timestamptz,
    status_changed_by     uuid REFERENCES accounts(id), -- This will be set to NOT NULL once we bootstrapped the first $system account

    locked_until          timestamptz,

    password_hash         text,
    mfa_enabled           boolean        NOT NULL DEFAULT false,
    mfa_secret            text,
    last_login_at         timestamptz,
    failed_login_attempts integer        NOT NULL DEFAULT 0,
    password_changed_at   timestamptz,
    must_change_password  boolean        NOT NULL DEFAULT false,

    passphrase_hash       text,
    public_key            text,

    full_name             text,
    email                 text,
    metadata              jsonb          NOT NULL DEFAULT '{}'::jsonb,

    created_at            timestamptz    NOT NULL DEFAULT now(),
    created_by            uuid REFERENCES accounts(id), -- This will be set to NOT NULL once we bootstrapped the first $system account
    updated_at            timestamptz,
    updated_by            uuid REFERENCES accounts(id),
    deleted_at            timestamptz,
    deleted_by            uuid REFERENCES accounts(id)
);

-- Constraints -----------------------------------------------------------------------------------------

ALTER TABLE accounts
    ADD CONSTRAINT accounts_name_length CHECK (char_length(name) BETWEEN 3 AND 64),
    ADD CONSTRAINT accounts_name_format CHECK (name ~ '^[\$a-zA-Z0-9\._-]+$');

ALTER TABLE accounts
    ADD CONSTRAINT system_accounts_prefix
        CHECK (
            (account_type = 'system' AND name LIKE '$%')
                OR
            (account_type <> 'system' AND name NOT LIKE '$%')
            );

ALTER TABLE accounts
    ADD CONSTRAINT password_by_type
        CHECK (
            (account_type = 'service' AND password_hash IS NULL)
                OR
            (account_type <> 'service')
            );

ALTER TABLE accounts
    ADD CONSTRAINT password_only_for_user
        CHECK (
            password_hash IS NULL OR account_type = 'user'
            );

ALTER TABLE accounts
    ADD CONSTRAINT locked_fields_consistency
        CHECK (
            (status = 'locked') OR (locked_until IS NULL)
            );


ALTER TABLE accounts
    ADD CONSTRAINT accounts_service_auth_one_of
        CHECK (
            (account_type <> 'service')
                OR
            ((passphrase_hash IS NOT NULL)::int + (public_key IS NOT NULL)::int <= 1)
            );

-- Indexes and Foreign Keys ---------------------------------------------------------------------------

CREATE UNIQUE INDEX accounts_name_unique
    ON accounts (lower(name))
    WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS accounts_metadata_gin
    ON accounts
        USING gin (metadata jsonb_path_ops)
    WHERE deleted_at IS NULL;

-- Population of initial system accounts --------------------------------------------------------------

-- Insert $system account first
INSERT INTO accounts (
    name,
    account_type,
    status,
    status_reason,
    status_changed_at,
    password_hash,
    mfa_enabled,
    full_name,
    metadata,
    created_at
) VALUES (
    '$system',
    'system',
    'active',
    'Built-in system principal',
    now(),
    NULL,
    false,
    'Hierarkey System Principal',
    '{
        "description": "Built-in system principal used for automated actions",
        "created_by_migration": true,
        "notes": "This account should not be deleted or modified.",
        "labels": {
            "account-type": "system"
        }
    }'::jsonb,
    now()
);

-- Self-reference the $system account
UPDATE accounts
SET created_by = id,
    status_changed_by = id
WHERE name = '$system';

-- Add the NOT NULL constraint after bootstrapping
ALTER TABLE accounts
    ALTER COLUMN created_by SET NOT NULL,
    ALTER COLUMN status_changed_by SET NOT NULL;

-- Now insert the other system accounts
INSERT INTO accounts (
    name,
    account_type,
    status,
    status_reason,
    status_changed_at,
    status_changed_by,
    password_hash,
    mfa_enabled,
    full_name,
    metadata,
    created_at,
    created_by
) VALUES (
    '$bootstrap',
    'system',
    'active',
    'Built-in system principal (bootstrap)',
    now(),
    (SELECT id FROM accounts WHERE name = '$system'),
    NULL,
    false,
    'Hierarkey Bootstrap Principal',
    '{
        "description": "Built-in system principal used during initial bootstrap",
        "created_by_migration": true,
        "notes": "This account should not be deleted or modified.",
        "labels": {
            "account-type": "system"
        }
    }'::jsonb,
    now(),
    (SELECT id FROM accounts WHERE name = '$system')
);

INSERT INTO accounts (
    name,
    account_type,
    status,
    status_reason,
    status_changed_at,
    status_changed_by,
    password_hash,
    mfa_enabled,
    full_name,
    metadata,
    created_at,
    created_by
) VALUES (
    '$recovery',
    'system',
    'active',
    'Built-in system recovery',
    now(),
    (SELECT id FROM accounts WHERE name = '$system'),
    NULL,
    false,
    'Hierarkey Recovery Principal',
    '{
        "description": "Built-in system principal used for recovery operations",
        "created_by_migration": true,
        "notes": "This account should not be deleted or modified.",
        "labels": {
            "account-type": "system"
        }
    }'::jsonb,
    now(),
    (SELECT id FROM accounts WHERE name = '$system')
);