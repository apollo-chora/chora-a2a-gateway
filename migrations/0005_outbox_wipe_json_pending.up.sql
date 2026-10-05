-- 0005_outbox_wipe_json_pending.up.sql
--
-- Outbox payload encoding migration (codebase-wide JSON→binary-protobuf fix
-- — task #33, chora-a2a-gateway slice).
--
-- Background
-- ----------
-- Pre-fix outbox rows on chora_a2a.a2a_outbox_events held JSON-marshalled
-- payload bytes that the binary-encoded event schemas reject at publish
-- time with "Invalid binary proto message". The dispatcher retries forever
-- (MaxAttempts=5 then deadletter) and the row never publishes.
--
-- Schema-attached topics emitted by chora-a2a-gateway (verified via the
-- chora-contracts events-flat schemas 2026-05-16 — all 10 are BINARY-encoded):
--
--   * chora.a2a.invocation.started.v1
--   * chora.a2a.invocation.completed.v1
--   * chora.a2a.invocation.failed.v1
--   * chora.a2a.invocation.guardrail_blocked.v1
--   * chora.a2a.contract.declared.v1
--   * chora.a2a.contract.approved.v1
--   * chora.a2a.contract.revoked.v1
--   * chora.a2a.external_agent.registered.v1
--   * chora.a2a.external_agent.suspended.v1
--   * chora.a2a.external_agent.deregistered.v1
--
-- Fix
-- ---
-- internal/adapter/outbox/protomarshal now emits canonical binary protobuf
-- bytes for those 10 topics. New rows written after the fix carry binary
-- bytes and publish cleanly.
--
-- This migration drains pre-fix JSON-payload rows out of the pending queue
-- so the dispatcher stops retrying them; rows that NEVER successfully
-- published (still 'pending') are safe to mark 'failed' — no downstream
-- subscriber ever saw them.
--
-- Replay strategy
-- ---------------
-- We mark-failed rather than translate-and-retry: the producer-side handlers
-- (ext_router contract / invocation / approve flows, grpc.Handler.Invoke,
-- closure subscriber) are idempotent on envelope.idempotency_key — replaying
-- the upstream HTTP / gRPC call (or the closure event handler) will emit a
-- fresh correctly-encoded outbox row. Translating JSON-decoded fields back
-- into the typed proto would be more error-prone than re-emission, and
-- these topics carry zero state-change semantics beyond the audit trail
-- (which is also preserved in chora_a2a.invocations / contracts / partner
-- registrations tables, the system-of-record).
--
-- Idempotent: re-running is a no-op (the WHERE clause matches no rows after
-- the first pass).
--
-- Topics WITHOUT an attached schema (partner.*, agid.*, byoa_key.*,
-- dns_txt.*, mcp.*, invocation.rate_limited / scope_denied, contract.*
-- published / deprecated / invoked / rejected) are NOT wiped — those publish
-- fine on the JSON fallback path today; their rows can continue draining.
UPDATE a2a_outbox_events
SET status          = 'failed',
    last_error      = 'codebase-wide outbox protobuf encoding fix #33 — pre-fix JSON-payload row drained',
    last_attempt_at = now()
WHERE status = 'pending'
  AND topic IN (
    'chora.a2a.invocation.started.v1',
    'chora.a2a.invocation.completed.v1',
    'chora.a2a.invocation.failed.v1',
    'chora.a2a.invocation.guardrail_blocked.v1',
    'chora.a2a.contract.declared.v1',
    'chora.a2a.contract.approved.v1',
    'chora.a2a.contract.revoked.v1',
    'chora.a2a.external_agent.registered.v1',
    'chora.a2a.external_agent.suspended.v1',
    'chora.a2a.external_agent.deregistered.v1'
  );
