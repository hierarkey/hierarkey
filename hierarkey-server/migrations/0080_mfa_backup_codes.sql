-- Add MFA backup codes storage.
-- Stored as a JSON array of bcrypt-hashed backup codes.
-- Codes are invalidated one-by-one on use by updating this column.

ALTER TABLE accounts
    ADD COLUMN mfa_backup_codes TEXT;

-- Add mfa_challenge to the token_purpose enum so the MFA challenge token
-- can be issued and validated.
-- ALTER TYPE ... ADD VALUE cannot run inside a transaction.
ALTER TYPE token_purpose ADD VALUE IF NOT EXISTS 'mfa_challenge';
