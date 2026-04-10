-- Add 'refresh' value to the token_scope enum.
-- ALTER TYPE ... ADD VALUE cannot run inside a transaction, so this migration
-- must be committed before any code that references the new value is deployed.

ALTER TYPE token_scope ADD VALUE IF NOT EXISTS 'refresh';
