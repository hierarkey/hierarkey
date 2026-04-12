-- SPDX-License-Identifier: AGPL-3.0-only
-- Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

-- Add row-level HMAC protection to rbac_role_rules.
-- NULL means the row was written before HMAC enforcement was introduced.
-- When the signing key is loaded, a NULL HMAC is treated as a violation.
ALTER TABLE rbac_role_rules
    ADD COLUMN IF NOT EXISTS row_hmac text;
