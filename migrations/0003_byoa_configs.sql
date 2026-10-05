-- =============================================================================
-- chora-a2a-gateway : 0003_byoa_configs.sql
--
-- BYOAConfig — Bring Your Own Agent model configuration aggregate.
-- Relocated from chora-familiar/migrations/018_create_byoa_configs.up.sql
-- per ADR-132 (A2A is the sole sanctioned external cross-project sync path)
-- + M12.2 Batch 4 BYOA relocation flag.
--
-- Database     : chora_a2a (NOT chora_familiar — legacy archived in Batch 5)
-- Domain       : Agent-to-Agent (5 core; ADR-132)
-- Date         : 2026-05-12
-- Architecture : Architecture Review locked 2026-05-07
--
-- CRITICAL invariants:
--   - api_key_ref stores encrypted references only (prefixed with "enc:"),
--     NEVER raw API keys. The low-level AES-GCM vault primitive
--     (internal/domain/byoa) produces the ciphertext stored elsewhere.
--   - Governance Gatekeeper override is NOT mutable here — Gatekeeper
--     ALWAYS uses the platform-controlled model regardless of any BYOA
--     config (Principle Conflict Resolution: Governance wins).
--   - RLS isolates per-tenant (uses chora.tenant_id session variable per
--     chora-a2a-gateway's existing convention from 0001_initial.sql).
-- =============================================================================

BEGIN;

CREATE TYPE byoa_provider AS ENUM ('openai', 'anthropic', 'google', 'custom');

CREATE TABLE IF NOT EXISTS byoa_configs (
    id                     UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id              UUID            NOT NULL,
    gcid                   UUID            NOT NULL,
    provider               byoa_provider   NOT NULL,
    model_id               TEXT            NOT NULL,
    api_key_ref            TEXT            NOT NULL
        CHECK (api_key_ref LIKE 'enc:%'),  -- Enforce encrypted reference prefix
    temperature            DOUBLE PRECISION NOT NULL DEFAULT 0.7
        CHECK (temperature >= 0 AND temperature <= 2),
    max_tokens             INTEGER         NOT NULL DEFAULT 4096
        CHECK (max_tokens > 0 AND max_tokens <= 128000),
    system_prompt_override TEXT,
    is_active              BOOLEAN         NOT NULL DEFAULT true,
    created_at             TIMESTAMPTZ     NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ     NOT NULL DEFAULT now(),
    deleted_at             TIMESTAMPTZ
);

-- One active config per (tenant_id, gcid); soft-delete aware.
CREATE UNIQUE INDEX idx_byoa_configs_tenant_gcid
    ON byoa_configs (tenant_id, gcid)
    WHERE deleted_at IS NULL;

CREATE INDEX idx_byoa_configs_gcid
    ON byoa_configs (gcid)
    WHERE deleted_at IS NULL;

CREATE INDEX idx_byoa_configs_tenant_id
    ON byoa_configs (tenant_id)
    WHERE deleted_at IS NULL;

CREATE TRIGGER trg_byoa_configs_updated_at
    BEFORE UPDATE ON byoa_configs
    FOR EACH ROW EXECUTE FUNCTION a2a_set_updated_at();

-- Row-Level Security. Matches the chora-a2a-gateway 0001_initial.sql
-- convention: chora.tenant_id session variable (NOT the legacy
-- app.current_tenant_id used by chora-familiar).
ALTER TABLE byoa_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE byoa_configs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON byoa_configs
    FOR ALL USING (tenant_id = current_setting('chora.tenant_id', true)::uuid);

COMMIT;
