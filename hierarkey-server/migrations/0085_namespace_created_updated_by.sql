-- SPDX-License-Identifier: AGPL-3.0-only
-- Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

-- Track which account created and last modified each namespace.
-- Both columns are nullable so that existing rows and system-actor operations
-- are handled gracefully.

ALTER TABLE namespaces
    ADD COLUMN created_by uuid REFERENCES accounts (id),
    ADD COLUMN updated_by uuid REFERENCES accounts (id);
