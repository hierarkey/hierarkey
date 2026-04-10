-- Add 'platform' to the rbac_target_kind enum.
-- This replaces the Account { name: "$system" } sentinel used for platform-level
-- RBAC administration (roles, rules, bindings).
ALTER TYPE rbac_target_kind ADD VALUE IF NOT EXISTS 'platform';
