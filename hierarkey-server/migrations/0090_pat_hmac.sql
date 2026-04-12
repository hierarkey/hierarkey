-- SPDX-License-Identifier: AGPL-3.0-only
-- Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

-- Add row-level HMAC protection to the pats table.
-- Covers: id, account_id, expires_at, purpose, revoked_at.
-- NULL means the row was written before HMAC enforcement was introduced.
ALTER TABLE pats
    ADD COLUMN IF NOT EXISTS row_hmac text;
