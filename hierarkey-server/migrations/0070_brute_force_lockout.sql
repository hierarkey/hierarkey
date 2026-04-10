-- Allow locked_until to be set on active accounts (brute-force temporary lockout).
ALTER TABLE accounts DROP CONSTRAINT locked_fields_consistency;

ALTER TABLE accounts
    ADD CONSTRAINT locked_fields_consistency
        CHECK (
            locked_until IS NULL OR status IN ('active', 'locked')
        );
