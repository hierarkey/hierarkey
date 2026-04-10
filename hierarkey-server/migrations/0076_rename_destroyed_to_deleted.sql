-- The application code uses ResourceStatus::Deleted (serialises as "deleted"), but the original
-- migrations used the value 'destroyed' for hard-deleted records.  This caused a mismatch: the
-- default search filter (`status != 'deleted'`) did not exclude 'destroyed' rows, and reading
-- those rows back caused a deserialization error because ResourceStatus has no "destroyed" variant.

-- Namespaces: fix CHECK constraint and migrate existing rows
ALTER TABLE namespaces DROP CONSTRAINT IF EXISTS namespaces_status_check;
UPDATE namespaces SET status = 'deleted' WHERE status = 'destroyed';
ALTER TABLE namespaces
    ADD CONSTRAINT namespaces_status_check
        CHECK (status IN ('active', 'disabled', 'deleted'));

-- Secrets: fix CHECK constraint (secret deletions are hard-deleted via cascade, but keep
-- the constraint consistent with ResourceStatus)
ALTER TABLE secrets DROP CONSTRAINT IF EXISTS secrets_status_check;
UPDATE secrets SET status = 'deleted' WHERE status = 'destroyed';
ALTER TABLE secrets
    ADD CONSTRAINT secrets_status_check
        CHECK (status IN ('active', 'disabled', 'deleted'));
