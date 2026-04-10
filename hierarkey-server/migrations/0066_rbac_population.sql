-- Type definitions -----------------------------------------------------------------------------------
-- Table definition -----------------------------------------------------------------------------------
-- Constraints ----------------------------------------------------------------------------------------
-- Indexes and Foreign Keys ---------------------------------------------------------------------------
-- Population -----------------------------------------------------------------------------------------

BEGIN;

INSERT INTO rbac_roles (name, metadata, is_system, created_at, created_by, updated_at, updated_by)
SELECT
    'platform:admin',
    jsonb_build_object('description', 'Administrator role with full permissions'),
    true,
    NOW(),
    sys.id,
    NOW(),
    sys.id
FROM accounts sys
WHERE sys.name = '$system'
ON CONFLICT (name) DO NOTHING;

WITH sys AS (SELECT id
    FROM accounts
    WHERE name = '$system'),
    admin_role AS (SELECT id
        FROM rbac_roles
        WHERE name = 'platform:admin'),

    ins_rule AS (
        INSERT INTO rbac_rules (
            effect,
            permission,
            target_kind,
            pattern_raw,
            condition,
            metadata,
            created_at, created_by,
            updated_at, updated_by
        )
        SELECT
            'allow'::rbac_effect,
            'platform:admin',
            'all'::rbac_target_kind,
            NULL::text,
            NULL::jsonb,
            jsonb_build_object('description', 'platform:admin wildcard for all targets'),
            NOW(),
            sys.id,
            NULL,
            NULL
        FROM sys
        WHERE NOT EXISTS (SELECT 1
            FROM rbac_rules r
            WHERE r.effect = 'allow'::rbac_effect
                AND r.permission = 'platform:admin'
                AND r.target_kind = 'all'::rbac_target_kind
                AND r.pattern_raw IS NULL)
            RETURNING id),
    admin_rule AS (
        SELECT id
        FROM ins_rule
        UNION ALL
        SELECT r.id
        FROM rbac_rules r
        WHERE r.effect = 'allow'::rbac_effect
            AND r.permission = 'platform:admin'
            AND r.target_kind = 'all'::rbac_target_kind
            AND r.pattern_raw IS NULL
        LIMIT 1)

INSERT
INTO rbac_role_rules (role_id, rule_id, created_at, created_by)
SELECT admin_role.id,
    admin_rule.id,
    NOW(),
    sys.id
FROM admin_role
    CROSS JOIN sys
    CROSS JOIN admin_rule
ON CONFLICT (role_id, rule_id) DO NOTHING;

COMMIT;
