-- =============================================================================
-- chora-a2a-gateway : 0008_closure_pseudonymisation_state.up.sql
--
-- Domain        : Agent-to-Agent (5 core; ADR-132)
-- Database      : chora_a2a
-- Story         : CHO-2198 (W0-F1 durability + W0-F5 error-honesty)
--
-- Durable ack/dedup state for the federated account-closure saga (Tier 3
-- D11 / ADR-184 / ADR-186), replacing the process-local
-- events.InMemoryClosureRepo (W0-F1 UNGATED-DEFECT — see
-- docs/references/w0-f1-inmemory-inventory.md §6 item 4). Today the repo is
-- gated on `pubsubClient != nil`, never on pool health, so this ack/dedup
-- state is lost on every pod restart, which can duplicate-process or
-- permanently stall the closure saga for this domain.
--
-- What this table is NOT: it does not itself redact any PII column. The
-- closure subscriber (internal/adapter/events/closure_subscriber.go) still
-- decides WHAT to tokenise from config/PII_Closure_Map.yaml at read time;
-- neither the prior in-memory repo NOR this pg-backed ClosureRepository
-- executes a real per-table UPDATE against a2a_contracts /
-- byoa_credentials / a2a_invocations / external_agent_identities /
-- api_keys / dns_txt_verifications — both only durably record THAT a
-- (tenant, gcid) pair has been processed and HOW MANY columns the map
-- declared (rows_touched is a declared-intent count from the PII map, not
-- an actual per-row UPDATE-affected count). Real per-table redaction is a
-- separate, deeper gap confirmed to apply identically across ALL 9
-- closure-saga services (see CHO-2198 durability report). This migration
-- only fixes DURABILITY of the ack/dedup signal.
--
-- Row semantics: INSERT-once via ON CONFLICT (tenant_id, gcid) DO NOTHING,
-- never UPDATEd by application code — existence of a (tenant_id, gcid) row
-- IS the "pseudonymised" flag (mirrors the in-memory repo's
-- `pseudonymed[gcid] = true`, now tenant-scoped: the in-memory version
-- collapsed the key to gcid-only, a latent cross-tenant dedup collision
-- fixed alongside this migration — see closure_subscriber.go). No
-- deleted_at: this is append-only operational/ack state, not domain
-- content (same soft-delete exemption class as delivery_logs /
-- idempotency_keys per ddd-enforcement.md §Soft Deletes Exceptions), and
-- MUST NOT be reversed by anything short of the saga's own compensation
-- path — which, per the account-closure-saga skill, is refused once
-- pseudonymisation has been ack'd (point of no return).
--
-- RLS DEVIATION FROM THE chora-notifications REFERENCE (0013): that
-- migration uses a STRICT `tenant_id = current_setting(...)::uuid` policy
-- because chora-notifications' PgxPoolQuerier already wraps tenant-scoped
-- queries in a `SET LOCAL chora.tenant_id` transaction. chora-a2a-gateway's
-- PgxPoolQuerier does NOT do this yet (see internal/adapter/pg/runtime.go —
-- bare pool.Exec/Query, no SET LOCAL wrapper); this is the SAME reality
-- 0007_mcp_configs.up.sql already documented and solved for, so this
-- migration copies THAT policy shape (permissive when the GUC is unset)
-- rather than the notifications strict form. A strict policy against a GUC
-- that is never set today would make every INSERT fail the RLS WITH CHECK
-- outright — worse than the in-memory fallback it replaces. Tenant
-- isolation for Pseudonymise/IsPseudonymised is enforced today at the
-- application layer via the bound tenant_id parameter (matches
-- partners/a2a_contracts/a2a_invocations/mcp_configs). Once SET LOCAL
-- chora.tenant_id lands (M14, ExtRouter), this policy starts enforcing for
-- free with no migration change.
--
-- Date : 2026-07-15
-- =============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS closure_pseudonymisation_state (
    id               UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        UUID         NOT NULL,
    gcid             UUID         NOT NULL,
    rows_touched     INTEGER      NOT NULL DEFAULT 0,
    pseudonymised_at TIMESTAMPTZ  NOT NULL DEFAULT now(),
    -- One durable ack per (tenant, gcid) — the natural idempotency key the
    -- ClosureRepository.Pseudonymise port operates on.
    UNIQUE (tenant_id, gcid)
);

-- Cross-tenant admin/debug lookup path ("has this GCID been closed in ANY
-- tenant this domain has rows for?"). The (tenant_id, gcid) UNIQUE
-- constraint above already covers the tenant-scoped lookup RLS/app queries
-- use; this is the gcid-only shape for O+ closure-pipeline visibility
-- (account-closure-saga skill "Admin O+ closure-pipeline visibility").
CREATE INDEX IF NOT EXISTS idx_closure_pseudonymisation_state_gcid
    ON closure_pseudonymisation_state (gcid);

-- RLS: permissive-when-unset (matches 0007_mcp_configs.up.sql — see the
-- migration header for why the strict notifications-style policy would be
-- unsafe here today).
ALTER TABLE closure_pseudonymisation_state ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON closure_pseudonymisation_state;
CREATE POLICY tenant_isolation ON closure_pseudonymisation_state
    FOR ALL USING (
        current_setting('chora.tenant_id', true) IS NULL
        OR current_setting('chora.tenant_id', true) = ''
        OR tenant_id = current_setting('chora.tenant_id', true)::uuid
    );

-- Self-contained grants (9999_grant_app_roles.sql already ran against the
-- live DB; new tables created afterwards need explicit grants — same
-- convention as 0007_mcp_configs.up.sql; ALTER DEFAULT PRIVILEGES alone has
-- previously caused 42501 on targeted/backdated migrations, see
-- reusable_gotcha_targeted_migration_skips_9999_grants_and_tracker_lineage_drift).
GRANT SELECT, INSERT, UPDATE, DELETE ON closure_pseudonymisation_state TO chora_a2a_app_rw;
GRANT SELECT ON closure_pseudonymisation_state TO chora_a2a_app_ro;

COMMIT;
