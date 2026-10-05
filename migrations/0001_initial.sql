-- =============================================================================
-- chora-a2a-gateway : 0001_initial.sql
--
-- Domain        : Agent-to-Agent (5 core; ADR-132)
-- Database      : chora_a2a
-- Author        : agent-a5e52e89b73ede1d2 (db-migrations-11-services)
-- Date          : 2026-05-08
-- Architecture  : Architecture Review locked 2026-05-07 (Tier 1 D1)
--
-- Aggregates owned by this database:
--   - Partners (registered external agent partners — keyed by AGID, NOT GCID)
--   - Contracts (capability + rate_limit + auth_method per partner)
--   - Invocations (per-call session log; append-only)
--   - ExternalAgentIdentity keys (Ed25519 PEM + fingerprint)
--
-- CRITICAL: NO gcid columns. Agents do NOT have GCIDs (CLAUDE.md §1 + ADR-132).
-- AGID is the agent identity, distinct from GCID.
-- =============================================================================

BEGIN;

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE OR REPLACE FUNCTION a2a_set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- -----------------------------------------------------------------------------
-- ENUMs
-- -----------------------------------------------------------------------------
CREATE TYPE partner_status        AS ENUM ('active', 'suspended');
CREATE TYPE invocation_status     AS ENUM ('started', 'completed', 'failed');
CREATE TYPE contract_auth_method  AS ENUM ('ed25519_jws', 'hmac_sha256', 'mtls');
CREATE TYPE agent_signing_alg     AS ENUM ('Ed25519');

-- -----------------------------------------------------------------------------
-- partners — registered external partners (AGID-keyed; tenant-scoped)
--
-- Per ADR-132: A Partner is a tenant-scoped binding to an external partner
-- identified by AGID (UUIDv7). NO gcid column.
-- -----------------------------------------------------------------------------
CREATE TABLE partners (
    agid              UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID            NOT NULL,
    org_name          VARCHAR(256)    NOT NULL,
    contact_email     VARCHAR(256)    NOT NULL,
    api_key_hash      CHAR(64)        NOT NULL,                  -- SHA-256 hex
    status            partner_status  NOT NULL DEFAULT 'active',
    suspended_at      TIMESTAMPTZ     NULL,
    suspend_reason    TEXT            NULL,
    rate_limit_per_min INTEGER        NOT NULL DEFAULT 0 CHECK (rate_limit_per_min >= 0),
    quota_per_day     INTEGER         NOT NULL DEFAULT 0 CHECK (quota_per_day >= 0),
    allowed_scopes    TEXT[]          NOT NULL DEFAULT '{}',
    created_at        TIMESTAMPTZ     NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ     NOT NULL DEFAULT now(),
    deleted_at        TIMESTAMPTZ     NULL,
    UNIQUE (tenant_id, org_name)
);

CREATE INDEX idx_partners_tenant ON partners (tenant_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_partners_status ON partners (status) WHERE deleted_at IS NULL;
CREATE INDEX idx_partners_apikey ON partners (api_key_hash);

CREATE TRIGGER trg_partners_updated_at
    BEFORE UPDATE ON partners
    FOR EACH ROW EXECUTE FUNCTION a2a_set_updated_at();

ALTER TABLE partners ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON partners
    FOR ALL USING (tenant_id = current_setting('chora.tenant_id', true)::uuid);

-- -----------------------------------------------------------------------------
-- contracts — capability + rate_limit + auth_method per partner
-- -----------------------------------------------------------------------------
CREATE TABLE contracts (
    contract_id       UUID                  PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID                  NOT NULL,
    agid              UUID                  NOT NULL REFERENCES partners(agid) ON DELETE RESTRICT,
    capabilities      JSONB                 NOT NULL DEFAULT '[]'::jsonb,  -- [{name, version}, ...]
    rate_limits       JSONB                 NOT NULL DEFAULT '{}'::jsonb,  -- {window: limit, ...}
    auth_method       contract_auth_method  NOT NULL,
    spec_version      VARCHAR(32)           NOT NULL DEFAULT 'v1',
    activated_at      TIMESTAMPTZ           NOT NULL DEFAULT now(),
    expires_at        TIMESTAMPTZ           NULL,
    created_at        TIMESTAMPTZ           NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ           NOT NULL DEFAULT now(),
    deleted_at        TIMESTAMPTZ           NULL
);

CREATE INDEX idx_contracts_tenant ON contracts (tenant_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_contracts_agid   ON contracts (agid) WHERE deleted_at IS NULL;
CREATE INDEX idx_contracts_caps_gin ON contracts USING GIN (capabilities);

CREATE TRIGGER trg_contracts_updated_at
    BEFORE UPDATE ON contracts
    FOR EACH ROW EXECUTE FUNCTION a2a_set_updated_at();

ALTER TABLE contracts ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON contracts
    FOR ALL USING (tenant_id = current_setting('chora.tenant_id', true)::uuid);

-- -----------------------------------------------------------------------------
-- agent_identities — Ed25519 public key + fingerprint per AGID
-- -----------------------------------------------------------------------------
CREATE TABLE agent_identities (
    agid              UUID               PRIMARY KEY REFERENCES partners(agid) ON DELETE RESTRICT,
    tenant_id         UUID               NOT NULL,
    public_key_pem    TEXT               NOT NULL,
    key_fingerprint   CHAR(64)           NOT NULL,           -- SHA-256 hex of PEM
    jwks_uri          TEXT               NULL,
    algorithm         agent_signing_alg  NOT NULL DEFAULT 'Ed25519',
    created_at        TIMESTAMPTZ        NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ        NOT NULL DEFAULT now()
);

CREATE INDEX idx_agent_identities_tenant ON agent_identities (tenant_id);
CREATE INDEX idx_agent_identities_fingerprint ON agent_identities (key_fingerprint);

CREATE TRIGGER trg_agent_identities_updated_at
    BEFORE UPDATE ON agent_identities
    FOR EACH ROW EXECUTE FUNCTION a2a_set_updated_at();

ALTER TABLE agent_identities ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent_identities
    FOR ALL USING (tenant_id = current_setting('chora.tenant_id', true)::uuid);

-- -----------------------------------------------------------------------------
-- invocations — APPEND-ONLY per-call session log
-- -----------------------------------------------------------------------------
CREATE TABLE invocations (
    invocation_id     UUID                PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID                NOT NULL,
    agid              UUID                NOT NULL REFERENCES partners(agid) ON DELETE RESTRICT,
    correlation_id    VARCHAR(128)        NOT NULL,
    capability        VARCHAR(128)        NOT NULL,
    status            invocation_status   NOT NULL DEFAULT 'started',
    latency_ms        INTEGER             NULL CHECK (latency_ms IS NULL OR latency_ms >= 0),
    response_size     INTEGER             NULL CHECK (response_size IS NULL OR response_size >= 0),
    error_code        VARCHAR(64)         NULL,
    traceparent       VARCHAR(64)         NULL,
    started_at        TIMESTAMPTZ         NOT NULL DEFAULT now(),
    ended_at          TIMESTAMPTZ         NULL,
    called_at         TIMESTAMPTZ         NOT NULL DEFAULT now()
);

CREATE INDEX idx_invocations_tenant     ON invocations (tenant_id);
CREATE INDEX idx_invocations_agid       ON invocations (agid);
CREATE INDEX idx_invocations_correl     ON invocations (correlation_id);
CREATE INDEX idx_invocations_status     ON invocations (status);
CREATE INDEX idx_invocations_called_at  ON invocations (called_at DESC);

CREATE OR REPLACE FUNCTION enforce_invocations_append_only()
RETURNS TRIGGER AS $$
BEGIN
    -- UPDATE is allowed ONLY for terminal-status writes (started -> completed/failed).
    -- DELETE is forbidden outright.
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'invocations is append-only: DELETE rejected';
    END IF;
    -- Reject mutation of started_at / agid / capability / correlation_id.
    IF TG_OP = 'UPDATE' THEN
        IF NEW.agid           <> OLD.agid           THEN RAISE EXCEPTION 'invocations.agid is immutable';           END IF;
        IF NEW.capability     <> OLD.capability     THEN RAISE EXCEPTION 'invocations.capability is immutable';     END IF;
        IF NEW.correlation_id <> OLD.correlation_id THEN RAISE EXCEPTION 'invocations.correlation_id is immutable'; END IF;
        IF NEW.started_at     <> OLD.started_at     THEN RAISE EXCEPTION 'invocations.started_at is immutable';     END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_invocations_immutable_update
    BEFORE UPDATE ON invocations
    FOR EACH ROW EXECUTE FUNCTION enforce_invocations_append_only();

CREATE TRIGGER trg_invocations_no_delete
    BEFORE DELETE ON invocations
    FOR EACH ROW EXECUTE FUNCTION enforce_invocations_append_only();

ALTER TABLE invocations ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON invocations
    FOR ALL USING (tenant_id = current_setting('chora.tenant_id', true)::uuid);

COMMIT;
