-- SPDX-License-Identifier: AGPL-3.0-only
-- Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

-- Stores external identity bindings for service accounts that authenticate
-- via a federated provider (OIDC, Kubernetes TokenReview, etc.).
--
-- Constraints:
--   - One service account can be linked to at most one federated identity (UNIQUE on account_id).
--   - One external identity (provider + issuer + subject) maps to at most one account.

CREATE TABLE federated_identities
(
    id               uuid        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    -- The service account this identity is linked to. One account = one identity.
    account_id       uuid        NOT NULL UNIQUE REFERENCES accounts (id),
    -- Matches the `id` field of the [[auth.federated]] config entry.
    provider_id      text        NOT NULL,
    -- Stable issuer string from the provider (OIDC issuer URL, k8s API server URL).
    external_issuer  text        NOT NULL,
    -- Stable unique subject from the provider (OIDC `sub` claim, k8s user UID/username).
    external_subject text        NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    created_by       uuid        NOT NULL REFERENCES accounts (id),

    -- Prevent the same external identity from being linked to multiple accounts.
    CONSTRAINT federated_identities_unique_identity
        UNIQUE (provider_id, external_issuer, external_subject)
);

CREATE INDEX federated_identities_account_id_idx ON federated_identities (account_id);
