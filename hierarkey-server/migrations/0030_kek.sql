-- Type definitions -----------------------------------------------------------------------------------
-- Table definition -----------------------------------------------------------------------------------

CREATE TABLE keks
(
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    short_id              text UNIQUE DEFAULT random_short_id('kek_', 12),

    algorithm        text        NOT NULL DEFAULT 'AES256-GCM',
    ciphertext       bytea       NOT NULL,
    masterkey_id    uuid        NOT NULL REFERENCES masterkeys(id) ON DELETE RESTRICT,
    rotation_count   integer     NOT NULL DEFAULT 0 CHECK (rotation_count >= 0),
    last_rotated_at  timestamptz,
    rotate_by        timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now(),
    deleted_at       timestamptz,
    CONSTRAINT keks_masterkeyfk
        FOREIGN KEY (masterkey_id)
        REFERENCES masterkeys(id)
        ON DELETE RESTRICT
);

-- Constraints ----------------------------------------------------------------------------------------
-- Indexes and Foreign Keys ---------------------------------------------------------------------------
-- Population -----------------------------------------------------------------------------------------
