-- Migration 0076 renamed the namespace status value 'destroyed' -> 'deleted', but the
-- partial unique index `namespaces_namespace_active_uniq` still uses `WHERE status <> 'destroyed'`.
-- Because 'destroyed' no longer exists, the condition is vacuously true for all rows, including
-- soft-deleted ('deleted') ones, which prevents name reuse after deletion.
-- Drop and recreate the index to use the correct status value.

DROP INDEX IF EXISTS namespaces_namespace_active_uniq;

CREATE UNIQUE INDEX namespaces_namespace_active_uniq
    ON namespaces (namespace)
    WHERE status <> 'deleted';
