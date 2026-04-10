-- Rename token_scope type and pats.scope column to reflect that this is a token
-- purpose (auth / change_pwd / refresh), not a permission scope.
ALTER TYPE token_scope RENAME TO token_purpose;
ALTER TABLE pats RENAME COLUMN scope TO purpose;
