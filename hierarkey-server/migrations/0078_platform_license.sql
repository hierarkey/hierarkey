-- Platform license storage.
-- At most one row may exist (enforced by the primary key value being fixed to 1).
CREATE TABLE platform_license (
    id           SMALLINT     PRIMARY KEY DEFAULT 1,
    license_json TEXT         NOT NULL,
    set_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT platform_license_single_row CHECK (id = 1)
);
