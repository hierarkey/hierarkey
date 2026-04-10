-- Type definitions -----------------------------------------------------------------------------------
-- Table definition -----------------------------------------------------------------------------------

CREATE TABLE namespace_kek_assignments
(
    namespace_id uuid NOT NULL REFERENCES namespaces(id) ON DELETE CASCADE,
    revision     integer NOT NULL CHECK (revision >= 1),
    is_active    boolean NOT NULL DEFAULT true,
    kek_id       uuid NOT NULL REFERENCES keks(id) ON DELETE RESTRICT,
    metadata     jsonb       DEFAULT '{}'::jsonb,
    created_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT namespace_keks_revision_uq PRIMARY KEY (namespace_id, revision)
);

-- Constraints ----------------------------------------------------------------------------------------
-- Indexes and Foreign Keys ---------------------------------------------------------------------------

CREATE INDEX namespace_kek_assignments_ns_rev_desc_idx
    ON namespace_kek_assignments (namespace_id, revision DESC);

CREATE UNIQUE INDEX namespace_kek_assignments_active_uq
    ON namespace_kek_assignments (namespace_id)
    WHERE is_active;

-- Population -----------------------------------------------------------------------------------------
