-- SPDX-License-Identifier: AGPL-3.0-only
-- Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

-- Shared nonce store for Ed25519 service-account authentication replay prevention.
-- Using the database instead of an in-process HashMap ensures that a nonce consumed
-- on one server instance cannot be replayed to a second instance in a multi-node
-- deployment. The PRIMARY KEY provides the atomic check-and-insert guarantee.
CREATE TABLE auth_nonces (
    nonce      TEXT        PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL
);

-- Used by the cleanup DELETE that runs on each consume call.
CREATE INDEX auth_nonces_expires_at_idx ON auth_nonces (expires_at);
