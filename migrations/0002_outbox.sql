-- =============================================================================
-- chora-a2a-gateway : 0002_outbox.sql
--
-- Adds the canonical D6.2 producer-side transactional outbox + DLQ tables
-- for chora-a2a-gateway's emitted chora.a2a.* event streams, per
-- `feedback_d6_resilience_first_class` B.6.2 sub-deliverable (a) and the
-- M12.3 outbox-templates plan (`docs/architecture/m12-3-outbox-templates-plan-2026-05-12.md`).
--
-- Mirrors:
--   services/chora-guardrail/migrations/0004_outbox.sql
--   services/chora-closure-orchestrator/migrations/0002_outbox.sql
--   services/chora-ai-kernel-orchestrator/migrations/0003_outbox.sql
--
-- Domain   : Agent-to-Agent (5 core; ADR-132 — A2A is a competitive-
--            advantage CORE domain, not an add-on; sole sanctioned external
--            cross-project sync path).
-- Database : chora_a2a — the domain DB that already owns the partner /
--            contract / invocation / byoa-key / mcp-config / dns / agid
--            tables. The outbox tables live alongside them so the
--            producer-side row write co-locates with the operational state
--            the request handler is already mutating.
-- Date     : 2026-05-12
--
-- HARD INVARIANTS
--   * tenant_id is captured as a top-level column (D6.3 multi-tenant
--     isolation indexing + RLS — production A2A invocations carry events
--     from many tenants through the same event bus pipe).
--   * idempotency_key + envelope mandatory per CLAUDE.md cross-cutting
--     rule (event envelope mandatory fields).
--   * Cross-DB queries remain forbidden — domain subscribers in other
--     chora-* services read events from event bus, never from this table.
--   * agid is a top-level column because A2A external-agent events
--     (chora.a2a.contract.*.v1, chora.a2a.agid.*.v1, chora.a2a.invocation.*.v1)
--     carry the calling agent identity (AGID ≠ GCID per
--     ddd-enforcement.md #10).
--
-- NOTE: This supersedes the pre-D6.2 outbox_events table created by the
-- earlier M11 pass (which used aggregate_type/aggregate_id columns but
-- lacked tenant_id top-level + RLS). The old table + checkpoints + dead
-- letters are dropped first; the canonical schema replaces them. The old
-- table was never wired to any production publisher path — chora-a2a-gateway
-- shipped to dev with the in-memory events.InMemoryPublisher fallback only.
-- =============================================================================

BEGIN;

-- Drop the pre-D6.2 outbox shape (no callers in production).
DROP TABLE IF EXISTS outbox_dead_letters;
DROP TABLE IF EXISTS outbox_poll_checkpoints;
DROP TABLE IF EXISTS outbox_events;
-- idempotency_keys is retained — separate concern (HTTP-level dedupe).

CREATE TABLE IF NOT EXISTS a2a_outbox_events (
    id              TEXT        PRIMARY KEY,                 -- UUIDv7 (event_id)
    tenant_id       UUID        NOT NULL,                    -- D6.3 isolation
    gcid            UUID,                                    -- subject (may be empty for system events)
    agid            TEXT        NOT NULL DEFAULT '',         -- agent identity (AGID — distinct from GCID per ddd-enforcement #10)
    event_type      TEXT        NOT NULL,                    -- e.g. 'a2a.contract.invoked'
    topic           TEXT        NOT NULL,                    -- 'chora.a2a.{aggregate}.{event_type}.v1'
    payload         BYTEA       NOT NULL,                    -- JSON (POC) / Protobuf bytes
    envelope        JSONB       NOT NULL,                    -- full envelope: event_id,
                                                             -- idempotency_key, traceparent,
                                                             -- tracestate, source_project,
                                                             -- source_service, schema_version
    idempotency_key TEXT        NOT NULL,                    -- dedupe key (from envelope)
    occurred_at     TIMESTAMPTZ NOT NULL,
    status          TEXT        NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending','published','failed','deadlettered')),
    retry_count     INT         NOT NULL DEFAULT 0,
    last_error      TEXT        NOT NULL DEFAULT '',
    last_attempt_at TIMESTAMPTZ,
    published_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Dispatcher poll query — find next pending event by occurred_at.
CREATE INDEX IF NOT EXISTS a2a_outbox_events_pending_idx
    ON a2a_outbox_events (occurred_at ASC) WHERE status = 'pending';

-- D6.3 multi-tenant isolation lookup: dispatcher MAY filter per-tenant.
CREATE INDEX IF NOT EXISTS a2a_outbox_events_tenant_idx
    ON a2a_outbox_events (tenant_id, status, occurred_at);

-- Per-topic dispatcher worker mode.
CREATE INDEX IF NOT EXISTS a2a_outbox_events_topic_idx
    ON a2a_outbox_events (topic, status);

-- Idempotency dedupe — re-emission of the same event collapses on this
-- unique index. Unique because dedupe MUST be exact.
CREATE UNIQUE INDEX IF NOT EXISTS a2a_outbox_events_idempotency_idx
    ON a2a_outbox_events (idempotency_key);

-- Dispatcher checkpoint — at most one row per (worker_id, topic).
-- Tracks the last successfully published event so the worker can resume
-- after a pod-death without re-publishing already-acked events.
CREATE TABLE IF NOT EXISTS a2a_outbox_dispatch_checkpoints (
    worker_id                  TEXT        NOT NULL,
    topic                      TEXT        NOT NULL,
    last_processed_outbox_id   TEXT        NOT NULL,
    last_processed_occurred_at TIMESTAMPTZ NOT NULL,
    updated_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (worker_id, topic)
);

CREATE INDEX IF NOT EXISTS a2a_outbox_dispatch_checkpoints_topic_idx
    ON a2a_outbox_dispatch_checkpoints (topic, updated_at DESC);

-- DLQ pointer — events that exceed max_retries land here. resolved_at
-- is set when an operator manually replays via the chora-a2a-gateway runbook
-- (per B.6.2 sub-deliverable d "Orchestrator-side DLQ awareness").
CREATE TABLE IF NOT EXISTS a2a_outbox_dead_letters (
    outbox_event_id   TEXT        PRIMARY KEY REFERENCES a2a_outbox_events(id),
    failure_reason    TEXT        NOT NULL,
    attempt_count     INT         NOT NULL,
    worker_id         TEXT        NOT NULL,
    deadlettered_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at       TIMESTAMPTZ,
    resolution_note   TEXT        NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS a2a_outbox_dead_letters_unresolved_idx
    ON a2a_outbox_dead_letters (deadlettered_at DESC) WHERE resolved_at IS NULL;

-- Multi-tenant RLS — same pattern as the closure outbox + AI Kernel outbox +
-- guardrail outbox. chora-a2a-gateway invocations are inherently multi-
-- tenant (one the service pod brokers calls from many tenants per second);
-- production wires the GUC via per-connection SET LOCAL app.current_tenant.
-- RLS policy remains permissive when the GUC is unset to keep the
-- dispatcher poll loop functional under the platform-level worker SA;
-- tenant isolation is also enforced at the application + envelope layer.
ALTER TABLE a2a_outbox_events ENABLE ROW LEVEL SECURITY;

CREATE POLICY a2a_outbox_events_tenant_isolation ON a2a_outbox_events
    USING (
        current_setting('app.current_tenant', TRUE) IS NULL
        OR current_setting('app.current_tenant', TRUE) = ''
        OR tenant_id::TEXT = current_setting('app.current_tenant', TRUE)
    );

COMMIT;
