-- =============================================================================
-- chora-a2a-gateway : 0006_oplus_repos.up.sql
--
-- Domain        : Agent-to-Agent (5 core; ADR-132)
-- Database      : chora_a2a
-- Author        : agent N6 (M12-backlog debt-clear)
-- Date          : 2026-05-26
--
-- Adds Postgres persistence for the three O+ aggregate repos that were
-- in-memory only since Phase B6-B7 (commit ce063558):
--
--   - partner_registrations  — partner.Registration workflow aggregate
--   - a2a_contracts          — contract.Contract aggregate (matches domain
--                              shape; distinct from the legacy `contracts`
--                              table created by 0001_initial.sql which is
--                              kept for the legacy `internal/adapter/inmem`
--                              path)
--   - a2a_invocations        — invocation.Invocation append-only audit log
--                              with `endpoint` + extended status enum
--                              (rate_limited / scope_denied)
--
-- CRITICAL: NO gcid columns. Agents do NOT have GCIDs (CLAUDE.md §1 + ADR-132).
-- AGID is the agent identity, distinct from GCID; partner_registrations
-- carries org-level data + AGID only.
--
-- Tenant scoping: per ADR-132 every aggregate is multi-tenant. RLS uses the
-- same `chora.tenant_id` GUC the M11 wave already wires.
-- =============================================================================

BEGIN;

-- -----------------------------------------------------------------------------
-- ENUMs — domain-faithful (the legacy 0001 enums diverged; we keep both for
-- the legacy adapter and add new ones here without breaking partner_repository).
-- -----------------------------------------------------------------------------
CREATE TYPE registration_state AS ENUM ('pending', 'approved', 'suspended');
CREATE TYPE registration_tier  AS ENUM ('low', 'medium', 'high', 'critical');
CREATE TYPE a2a_contract_auth  AS ENUM ('api_key', 'jws_ed25519', 'oauth2');
CREATE TYPE a2a_invocation_status AS ENUM (
    'started', 'completed', 'failed', 'rate_limited', 'scope_denied'
);

-- -----------------------------------------------------------------------------
-- partner_registrations — workflow aggregate per ADR-132 §8 partner onboarding
-- -----------------------------------------------------------------------------
CREATE TABLE partner_registrations (
    id                    UUID                  PRIMARY KEY,
    tenant_id             UUID                  NOT NULL,
    org_name              VARCHAR(256)          NOT NULL,
    contact_email         VARCHAR(256)          NOT NULL,
    capabilities          TEXT[]                NOT NULL DEFAULT '{}',
    requested_rate_limit  INTEGER               NOT NULL CHECK (requested_rate_limit >= 0),

    state                 registration_state    NOT NULL DEFAULT 'pending',
    tier                  registration_tier     NULL,

    agid                  VARCHAR(128)          NULL,
    api_key_hash          CHAR(64)              NULL,

    approved_by_gcid      VARCHAR(64)           NULL,
    approved_at           TIMESTAMPTZ           NULL,

    suspended_by_gcid     VARCHAR(64)           NULL,
    suspended_at          TIMESTAMPTZ           NULL,
    suspend_reason        TEXT                  NULL,

    partner_domain        TEXT                  NULL,
    dns_verify_token      TEXT                  NULL,
    dns_verified          BOOLEAN               NOT NULL DEFAULT FALSE,
    dns_verified_at       TIMESTAMPTZ           NULL,

    created_at            TIMESTAMPTZ           NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ           NOT NULL DEFAULT now(),
    deleted_at            TIMESTAMPTZ           NULL
);

CREATE INDEX idx_partner_registrations_tenant
    ON partner_registrations (tenant_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_partner_registrations_state
    ON partner_registrations (state) WHERE deleted_at IS NULL;
CREATE INDEX idx_partner_registrations_agid
    ON partner_registrations (agid) WHERE deleted_at IS NULL AND agid IS NOT NULL;
CREATE INDEX idx_partner_registrations_created_at
    ON partner_registrations (created_at) WHERE deleted_at IS NULL;

CREATE TRIGGER trg_partner_registrations_updated_at
    BEFORE UPDATE ON partner_registrations
    FOR EACH ROW EXECUTE FUNCTION a2a_set_updated_at();

ALTER TABLE partner_registrations ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON partner_registrations
    FOR ALL USING (
        current_setting('chora.tenant_id', true) IS NULL
        OR current_setting('chora.tenant_id', true) = ''
        OR tenant_id = current_setting('chora.tenant_id', true)::uuid
    );

-- -----------------------------------------------------------------------------
-- a2a_contracts — A2AContract aggregate (domain shape)
--
-- The legacy `contracts` table (0001_initial.sql) uses a different auth_method
-- enum + an FK to `partners(agid)`. The new table mirrors the contract.Contract
-- aggregate exactly (capabilities as JSONB, version + supersedes_id columns).
-- -----------------------------------------------------------------------------
CREATE TABLE a2a_contracts (
    id            UUID                 PRIMARY KEY,
    tenant_id     UUID                 NOT NULL,
    partner_id    UUID                 NOT NULL,
    auth_method   a2a_contract_auth    NOT NULL,
    capabilities  JSONB                NOT NULL DEFAULT '[]'::jsonb,

    version        INTEGER             NOT NULL DEFAULT 1 CHECK (version >= 1),
    supersedes_id  UUID                NULL,
    sunset_at      TIMESTAMPTZ         NULL,

    created_at    TIMESTAMPTZ          NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ          NOT NULL DEFAULT now(),
    deleted_at    TIMESTAMPTZ          NULL
);

CREATE INDEX idx_a2a_contracts_tenant
    ON a2a_contracts (tenant_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_a2a_contracts_partner
    ON a2a_contracts (partner_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_a2a_contracts_created_at
    ON a2a_contracts (created_at) WHERE deleted_at IS NULL;
CREATE INDEX idx_a2a_contracts_caps_gin
    ON a2a_contracts USING GIN (capabilities);

CREATE TRIGGER trg_a2a_contracts_updated_at
    BEFORE UPDATE ON a2a_contracts
    FOR EACH ROW EXECUTE FUNCTION a2a_set_updated_at();

ALTER TABLE a2a_contracts ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON a2a_contracts
    FOR ALL USING (
        current_setting('chora.tenant_id', true) IS NULL
        OR current_setting('chora.tenant_id', true) = ''
        OR tenant_id = current_setting('chora.tenant_id', true)::uuid
    );

-- -----------------------------------------------------------------------------
-- a2a_invocations — append-only audit log with domain status enum + endpoint
--
-- The legacy `invocations` table (0001_initial.sql) uses an `invocation_status`
-- enum limited to started/completed/failed — domain has 5 states. The new
-- table mirrors invocation.Invocation exactly + adds the `endpoint` column
-- the O+ A2A console surfaces.
--
-- Append-only enforced via trigger: DELETE forbidden; UPDATE allowed only when
-- agid + capability + correlation_id + started_at are unchanged. Mirrors the
-- legacy trigger from 0001_initial.sql.
-- -----------------------------------------------------------------------------
CREATE TABLE a2a_invocations (
    id                    UUID                       PRIMARY KEY,
    tenant_id             UUID                       NOT NULL,
    agid                  VARCHAR(128)               NOT NULL,
    partner_id            UUID                       NOT NULL,
    capability            VARCHAR(128)               NOT NULL,
    correlation_id        VARCHAR(128)               NOT NULL,
    status                a2a_invocation_status      NOT NULL DEFAULT 'started',
    latency_ms            INTEGER                    NOT NULL DEFAULT 0 CHECK (latency_ms >= 0),
    response_size_bytes   INTEGER                    NOT NULL DEFAULT 0 CHECK (response_size_bytes >= 0),
    error_code            VARCHAR(64)                NOT NULL DEFAULT '',
    started_at            TIMESTAMPTZ                NOT NULL DEFAULT now(),
    ended_at              TIMESTAMPTZ                NULL,
    traceparent           VARCHAR(64)                NOT NULL DEFAULT '',
    endpoint              TEXT                       NOT NULL DEFAULT ''
);

CREATE INDEX idx_a2a_invocations_tenant    ON a2a_invocations (tenant_id);
CREATE INDEX idx_a2a_invocations_partner   ON a2a_invocations (partner_id);
CREATE INDEX idx_a2a_invocations_agid      ON a2a_invocations (agid);
CREATE INDEX idx_a2a_invocations_correl    ON a2a_invocations (correlation_id);
CREATE INDEX idx_a2a_invocations_status    ON a2a_invocations (status);
CREATE INDEX idx_a2a_invocations_started   ON a2a_invocations (started_at DESC);

CREATE OR REPLACE FUNCTION enforce_a2a_invocations_append_only()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'a2a_invocations is append-only: DELETE rejected';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF NEW.agid           <> OLD.agid           THEN RAISE EXCEPTION 'a2a_invocations.agid is immutable';           END IF;
        IF NEW.capability     <> OLD.capability     THEN RAISE EXCEPTION 'a2a_invocations.capability is immutable';     END IF;
        IF NEW.correlation_id <> OLD.correlation_id THEN RAISE EXCEPTION 'a2a_invocations.correlation_id is immutable'; END IF;
        IF NEW.started_at     <> OLD.started_at     THEN RAISE EXCEPTION 'a2a_invocations.started_at is immutable';     END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_a2a_invocations_immutable_update
    BEFORE UPDATE ON a2a_invocations
    FOR EACH ROW EXECUTE FUNCTION enforce_a2a_invocations_append_only();

CREATE TRIGGER trg_a2a_invocations_no_delete
    BEFORE DELETE ON a2a_invocations
    FOR EACH ROW EXECUTE FUNCTION enforce_a2a_invocations_append_only();

ALTER TABLE a2a_invocations ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON a2a_invocations
    FOR ALL USING (
        current_setting('chora.tenant_id', true) IS NULL
        OR current_setting('chora.tenant_id', true) = ''
        OR tenant_id = current_setting('chora.tenant_id', true)::uuid
    );

COMMIT;
