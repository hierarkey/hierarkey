-- Add client IP binding for refresh tokens.
ALTER TABLE pats ADD COLUMN IF NOT EXISTS created_from_ip TEXT;
