-- SPDX-License-Identifier: AGPL-3.0-only
-- Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

-- ALTER TYPE ... ADD VALUE cannot run inside a transaction, so this migration
-- must execute outside the default transaction that sqlx-migrate wraps around
-- each file.  sqlx supports this via the `-- no-transaction` pragma below.
-- no-transaction

-- Add the 'tampered' status for accounts whose row-level HMAC check failed.
-- The server sets this automatically when it detects that a row was modified
-- outside the application.  A tampered account cannot log in until an
-- administrator investigates and manually recovers or deletes the account.
ALTER TYPE account_status ADD VALUE IF NOT EXISTS 'tampered';
