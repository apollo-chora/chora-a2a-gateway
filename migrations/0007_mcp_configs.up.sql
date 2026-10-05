-- =============================================================================
-- chora-a2a-gateway : 0007_mcp_configs.up.sql
--
-- Domain        : Agent-to-Agent (5 core; ADR-132)
-- Database      : chora_a2a
-- Date          : 2026-07-01
--
-- Durable Postgres persistence for the per-tenant MCP-as-a-Service add-on
-- config (ADR-132 §10) — previously in-memory only
-- (internal/adapter/repo/inmem.MCPConfigRepo), which meant every registered
-- MCP partner API key was wiped on pod restart/rollout. Adds:
--
--   - mcp_configs — one row per tenant (tenant_id PK; a fresh
--     POST /admin/mcp/{tenant_id} upserts a brand-new key + allowlist,
--     mirroring partner_registrations' ON CONFLICT DO UPDATE convention
--     from 0006_oplus_repos.up.sql).
--
-- api_key_hash carries the SHA-256 hex digest of the add-on's credential
-- (partner.HashAPIKey) — NEVER the plaintext key. The unique partial index
-- below is the pre-tenant reverse lookup POST /admin/mcp/_resolve depends on
-- (internal/domain/mcp.Resolver.Resolve -> Store.ByAPIKeyHash): resolving
-- WHICH tenant owns a presented key necessarily runs before any tenant
-- context exists, so that one query is intentionally NOT tenant_id-scoped —
-- see internal/adapter/repo/pg/mcpconfig.go for the full rationale.
--
-- CRITICAL: NO gcid columns. The MCP add-on is an AGID-only agent identity,
-- not a GCID (CLAUDE.md §1 + ADR-132).
-- =============================================================================

BEGIN;

CREATE TABLE mcp_configs (
    tenant_id      UUID          PRIMARY KEY,
    api_key_hash   CHAR(64)      NOT NULL,              -- SHA-256 hex (partner.HashAPIKey)
    allowed_tools  TEXT[]        NOT NULL DEFAULT '{}',  -- MCP tool allowlist
    suspended      BOOLEAN       NOT NULL DEFAULT FALSE, -- reversible admin pause
    created_at     TIMESTAMPTZ   NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ   NOT NULL DEFAULT now(),
    deleted_at     TIMESTAMPTZ   NULL                    -- permanent revoke (soft-delete)
);

-- Pre-tenant reverse lookup: resolve an opaque partner key to the tenant
-- that owns it. Soft-delete-aware (a revoked key is never live twice) and
-- UNIQUE (defence-in-depth — two live tenants must never share a hash),
-- mirroring idx_byoa_configs_tenant_gcid's "UNIQUE ... WHERE deleted_at IS
-- NULL" idiom from 0003_byoa_configs.sql.
CREATE UNIQUE INDEX idx_mcp_configs_api_key_hash
    ON mcp_configs (api_key_hash)
    WHERE deleted_at IS NULL;

CREATE TRIGGER trg_mcp_configs_updated_at
    BEFORE UPDATE ON mcp_configs
    FOR EACH ROW EXECUTE FUNCTION a2a_set_updated_at();

-- RLS: matches the 0006_oplus_repos.up.sql convention (NOT the stricter
-- 0003_byoa_configs.sql FORCE RLS) — permissive when chora.tenant_id is
-- unset, which is the CURRENT reality for every pg query this service
-- issues (internal/adapter/pg/runtime.go's PgxPoolQuerier issues bare
-- pool.Exec/Query, no `SET LOCAL` transaction wrapper). Tenant isolation
-- for the tenant-scoped methods — Put/Get/SetSuspended — is enforced today
-- at the application layer via the bound tenant_id parameter, exactly like
-- partner_registrations/a2a_contracts/a2a_invocations already do. Once
-- SET LOCAL chora.tenant_id lands, this policy starts enforcing for free
-- with no migration change.
ALTER TABLE mcp_configs ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON mcp_configs
    FOR ALL USING (
        current_setting('chora.tenant_id', true) IS NULL
        OR current_setting('chora.tenant_id', true) = ''
        OR tenant_id = current_setting('chora.tenant_id', true)::uuid
    );

COMMIT;
