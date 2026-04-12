-- SPDX-License-Identifier: AGPL-3.0-only
-- Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

-- Add row-level HMAC columns to all tables that need integrity protection.
-- NULL means the row was created before HMAC enforcement was introduced (or
-- before a signing key was provisioned).  The application treats NULL the
-- same as an unsigned row and will re-sign it on the next write.

ALTER TABLE accounts
    ADD COLUMN IF NOT EXISTS row_hmac text;

ALTER TABLE rbac_rules
    ADD COLUMN IF NOT EXISTS row_hmac text;

ALTER TABLE rbac_account_rules
    ADD COLUMN IF NOT EXISTS row_hmac text;

ALTER TABLE rbac_account_roles
    ADD COLUMN IF NOT EXISTS row_hmac text;
