-- Replace the hard unique constraint on (namespace_id, ref_key) with a partial
-- unique index that only applies to non-deleted secrets.  This allows a new
-- secret to be created with the same name as a previously deleted secret
-- (the deleted record remains in the table for audit / restore purposes, but
-- the unique constraint no longer blocks the INSERT).

ALTER TABLE secrets DROP CONSTRAINT IF EXISTS secrets_namespace_ref_unique;

CREATE UNIQUE INDEX secrets_namespace_ref_not_deleted_unique
    ON secrets (namespace_id, ref_key)
    WHERE deleted_at IS NULL;
