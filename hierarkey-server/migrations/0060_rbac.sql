-- Type definitions -----------------------------------------------------------------------------------
DO
$$
    BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'rbac_effect') THEN
            CREATE TYPE rbac_effect AS ENUM ('allow', 'deny');
        END IF;

        IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'rbac_target_kind') THEN
            CREATE TYPE rbac_target_kind AS ENUM ('all', 'namespace', 'secret', 'account');
        END IF;
    END
$$;

-- Table definition -----------------------------------------------------------------------------------
-- Constraints ----------------------------------------------------------------------------------------
-- Indexes and Foreign Keys ---------------------------------------------------------------------------
-- Population -----------------------------------------------------------------------------------------


