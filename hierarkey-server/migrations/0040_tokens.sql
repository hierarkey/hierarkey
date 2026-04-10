-- Type definitions -----------------------------------------------------------------------------------

CREATE TYPE token_scope AS ENUM ('auth', 'change_pwd');

-- Table definition -----------------------------------------------------------------------------------

CREATE TABLE pats (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    short_id        text UNIQUE DEFAULT random_short_id('tok_', 12),

    account_id      uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    description     text,
    token_hash      bytea NOT NULL UNIQUE,
    token_suffix    text NOT NULL,
    scope           token_scope NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz,
    last_used_at    timestamptz,
    revoked_at      timestamptz,
    revoked_by      uuid REFERENCES accounts(id) ON DELETE SET NULL,
    usage_count     bigint NOT NULL DEFAULT 0,
    metadata        jsonb DEFAULT '{}'::jsonb,
    CONSTRAINT pat_token_suffix_length CHECK (char_length(token_suffix) = 4),
    CONSTRAINT pat_valid_expiration CHECK (expires_at IS NULL OR expires_at > created_at)
);

-- Constraints ----------------------------------------------------------------------------------------
-- Indexes and Foreign Keys ---------------------------------------------------------------------------


CREATE UNIQUE INDEX pat_token_hash_idx
    ON pats(token_hash)
    WHERE revoked_at IS NULL;

CREATE INDEX pat_user_active_idx
    ON pats(account_id, created_at DESC)
    WHERE revoked_at IS NULL;

CREATE INDEX pat_expired_idx
    ON pats(expires_at)
    WHERE expires_at IS NOT NULL AND revoked_at IS NULL;

CREATE INDEX pat_revoked_cleanup_idx
    ON pats(revoked_at)
    WHERE revoked_at IS NOT NULL;

CREATE INDEX pat_last_used_idx
    ON pats(last_used_at DESC NULLS LAST)
    WHERE revoked_at IS NULL;

CREATE INDEX pat_user_suffix_idx
    ON pats(account_id, token_suffix)
    WHERE revoked_at IS NULL;

CREATE INDEX pat_metadata_gin_idx
    ON pats USING gin (metadata);

-- Population -----------------------------------------------------------------------------------------
