-- Type definitions -----------------------------------------------------------------------------------
-- Table definition -----------------------------------------------------------------------------------

CREATE TABLE secret_revisions
(
    id               uuid PRIMARY KEY     DEFAULT gen_random_uuid(),
    short_id         text UNIQUE          DEFAULT random_short_id('sr_', 12),

    secret_id        uuid        NOT NULL REFERENCES secrets (id),
    revision         integer     NOT NULL DEFAULT 1 CHECK (revision >= 1),
    encrypted_secret bytea       NOT NULL,
    encrypted_dek    bytea       NOT NULL,
    kek_id           uuid        NOT NULL REFERENCES keks (id),
    secret_alg       text        NOT NULL,
    dek_alg          text        NOT NULL,
    metadata         jsonb       NOT NULL DEFAULT '{}'::jsonb,
    created_at       timestamptz NOT NULL DEFAULT now(),
    deleted_at       timestamptz
);

-- Constraints ----------------------------------------------------------------------------------------

ALTER TABLE secret_revisions
    ADD CONSTRAINT secret_revisions_secret_revision_unique UNIQUE (secret_id, revision);

-- Indexes and Foreign Keys ---------------------------------------------------------------------------

CREATE INDEX secret_revisions_secret_rev_desc_idx
    ON secret_revisions (secret_id, revision DESC);

CREATE INDEX secret_revisions_secret_rev_desc_not_deleted_idx
    ON secret_revisions (secret_id, revision DESC)
    WHERE deleted_at IS NULL;

CREATE INDEX secret_revisions_kek_id_idx
    ON secret_revisions (kek_id);

CREATE INDEX secret_revisions_metadata_gin_idx
    ON secret_revisions USING gin (metadata jsonb_path_ops);

-- Population -----------------------------------------------------------------------------------------