-- Audit event log for commercial license holders.
-- The table is always created by this migration (community and commercial share the same
-- schema), but rows are only ever written when the active license includes Feature::Audit.
--
-- chain_hash provides tamper-evidence: each row hashes itself together with the previous
-- row's chain_hash, forming an append-only chain that can be verified via /v1/audit/verify.

CREATE TABLE audit_events
(
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    seq           bigserial   NOT NULL UNIQUE,

    -- What happened
    event_type    text        NOT NULL,
    outcome       text        NOT NULL CHECK (outcome IN ('success', 'failure', 'denied')),

    -- Who did it (denormalized so records survive account deletion)
    actor_id      uuid,
    actor_type    text,
    actor_name    text,

    -- What it acted on (denormalized for the same reason)
    resource_type text,
    resource_id   uuid,
    resource_name text,

    -- Request correlation
    request_id    text,
    trace_id      text,
    client_ip     text,

    -- Arbitrary event-specific detail
    metadata      jsonb,

    created_at    timestamptz NOT NULL DEFAULT now(),

    -- SHA-256 hex digest over (prev_chain_hash || ":" || id || ":" || event_type ||
    -- ":" || outcome || ":" || created_at_nanos). Genesis row uses empty string as prev.
    chain_hash    text        NOT NULL
);

-- Common query patterns
CREATE INDEX audit_events_created_at_idx   ON audit_events (created_at DESC);
CREATE INDEX audit_events_actor_id_idx     ON audit_events (actor_id)   WHERE actor_id IS NOT NULL;
CREATE INDEX audit_events_resource_id_idx  ON audit_events (resource_id) WHERE resource_id IS NOT NULL;
CREATE INDEX audit_events_event_type_idx   ON audit_events (event_type);
CREATE INDEX audit_events_outcome_idx      ON audit_events (outcome);
