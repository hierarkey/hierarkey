-- Add 'draining' status to masterkey_status enum.
-- A draining master key is no longer used to wrap new KEKs (superseded by a new
-- active key) but still has existing KEKs wrapped under it. It must stay loaded
-- in the keyring until all KEKs are rewrapped away from it, at which point it
-- transitions to 'retired'.
--
-- 'disabled' is removed from the design: migrate any existing disabled rows to
-- 'retired'. PostgreSQL does not support dropping enum values, so 'disabled'
-- remains in the DB type but is no longer set by the application.

ALTER TYPE masterkey_status ADD VALUE IF NOT EXISTS 'draining';

UPDATE masterkeys SET status = 'retired', retired_at = COALESCE(retired_at, NOW())
WHERE status = 'disabled';

-- Relax the retire_consistency constraint.
-- The old constraint required retired_at IS NOT NULL for every retired row, which
-- broke freshly-created keys that start in 'retired' state (never been active).
-- New rule: non-retired/non-draining keys must NOT have retired_at set; retired
-- keys may have it null (born retired) or non-null (transitioned from active/draining).
ALTER TABLE masterkeys DROP CONSTRAINT masterkeys_retire_consistency;
-- Relaxed constraint: only 'active' keys are required to have no retired_at.
-- 'draining' keys never have retired_at (they haven't been fully retired yet).
-- 'retired' keys may have retired_at set (transitioned from active) or null
-- (created directly as retired and never activated).
ALTER TABLE masterkeys ADD CONSTRAINT masterkeys_retire_consistency CHECK (
    status != 'active' OR (retired_at IS NULL AND retired_by IS NULL)
);
