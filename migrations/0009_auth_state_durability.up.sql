-- =============================================================================
-- chora-a2a-gateway : 0009_auth_state_durability.up.sql
--
-- Domain        : Agent-to-Agent (5 core; ADR-132)
-- Database      : chora_a2a
-- Date          : 2026-07-16
-- Refs          : W0-F1 durability gate, CHO-2198
--
-- Closes the two AUTH-state durability gaps the report-only durability guard
-- (durabilityguard.Guard in cmd/server/main.go) surfaced as VIOLATIONs on a
-- live pool — both stores previously served AUTH/identity state from in-process
-- Go maps that evaporate on every pod restart/rollout:
--
--   - byoa_keys                — BYOA external-LLM provider-key vault (partner
--                                API-key ciphertext + SHA-256 fingerprint).
--                                Was internal/adapter/repo/inmem.BYOAKeyRepo.
--                                Keyed by (tenant_id, provider). DISTINCT from
--                                byoa_configs (0003), which stores the separate
--                                BYOAConfig model-config aggregate (tenant, gcid).
--   - external_agent_identities — ExternalAgentIdentity aggregate (partner
--                                agent Ed25519 public-key PEM + fingerprint the
--                                O+ A2A console reads, ADR-132 §3). Was the
--                                legacy internal/adapter/inmem.IdentityStore.
--                                Keyed by AGID (the `agid:{partner}:{cap}:{inst}`
--                                string minted by partner.MintAGID — NOT a UUID,
--                                hence VARCHAR(128), matching
--                                partner_registrations.agid).
--
-- CRITICAL: NO gcid columns. AGID is the agent identity, distinct from GCID
-- (CLAUDE.md §1 + ADR-132). Agents hold no TenantMembership + no closure saga.
--
-- Tenant scoping: RLS mirrors the 0006_oplus_repos / 0007_mcp_configs
-- convention (ENABLE, permissive when chora.tenant_id is unset) — NOT the
-- stricter 0003 FORCE policy — because the current pg wiring
-- (internal/adapter/pg/runtime.go's PgxPoolQuerier) issues bare pool.Exec/Query
-- with no `SET LOCAL chora.tenant_id` wrapper, so every tenant-scoped query in
-- this service enforces isolation at the application layer via the bound
-- tenant_id parameter. Once SET LOCAL chora.tenant_id lands, these policies
-- enforce for free with no migration change.
--
-- GRANTs: self-contained (the 42501 lesson) — 9999_grant_app_roles.sql already
-- ran on live DBs, so a targeted apply of this file would otherwise leave
-- chora_a2a_app_rw / _app_ro with zero privileges on the new tables.
-- =============================================================================

BEGIN;

-- -----------------------------------------------------------------------------
-- byoa_keys — BYOA external-LLM provider-key vault (AUTH state)
-- -----------------------------------------------------------------------------
CREATE TABLE byoa_keys (
    id               UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        UUID          NOT NULL,
    provider         TEXT          NOT NULL,              -- "openai" | "anthropic" | "vertex_byok" (free-form)
    ciphertext       BYTEA         NOT NULL,              -- AES-GCM nonce||ciphertext-with-tag (byoa.EncryptKey)
    key_fingerprint  CHAR(64)      NOT NULL,              -- SHA-256 hex of plaintext (audit anchor only)
    rotated_at       TIMESTAMPTZ   NOT NULL DEFAULT now(),
    created_at       TIMESTAMPTZ   NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ   NOT NULL DEFAULT now(),
    deleted_at       TIMESTAMPTZ   NULL,                  -- revocation (soft-delete)

    -- One live row per (tenant, provider); Put upserts on this key and clears
    -- any prior tombstone (matches inmem.BYOAKeyRepo's map-replace semantics),
    -- so an unconditional UNIQUE is correct + is the ON CONFLICT arbiter.
    UNIQUE (tenant_id, provider)
);

CREATE INDEX idx_byoa_keys_tenant
    ON byoa_keys (tenant_id) WHERE deleted_at IS NULL;

CREATE TRIGGER trg_byoa_keys_updated_at
    BEFORE UPDATE ON byoa_keys
    FOR EACH ROW EXECUTE FUNCTION a2a_set_updated_at();

ALTER TABLE byoa_keys ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON byoa_keys
    FOR ALL USING (
        current_setting('chora.tenant_id', true) IS NULL
        OR current_setting('chora.tenant_id', true) = ''
        OR tenant_id = current_setting('chora.tenant_id', true)::uuid
    );

-- -----------------------------------------------------------------------------
-- external_agent_identities — ExternalAgentIdentity aggregate (AGID public key)
-- -----------------------------------------------------------------------------
CREATE TABLE external_agent_identities (
    agid             VARCHAR(128)  PRIMARY KEY,           -- agid:{partner}:{cap}:{inst} (partner.MintAGID) — NOT a UUID
    tenant_id        UUID          NOT NULL,
    public_key_pem   TEXT          NOT NULL,
    key_fingerprint  CHAR(64)      NOT NULL,              -- SHA-256 hex of the PEM
    jwks_uri         TEXT          NOT NULL DEFAULT '',
    algorithm        VARCHAR(32)   NOT NULL,              -- "Ed25519" (agent_signing_alg)
    created_at       TIMESTAMPTZ   NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ   NOT NULL DEFAULT now(),
    deleted_at       TIMESTAMPTZ   NULL
);

CREATE INDEX idx_external_agent_identities_tenant
    ON external_agent_identities (tenant_id) WHERE deleted_at IS NULL;

CREATE TRIGGER trg_external_agent_identities_updated_at
    BEFORE UPDATE ON external_agent_identities
    FOR EACH ROW EXECUTE FUNCTION a2a_set_updated_at();

ALTER TABLE external_agent_identities ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON external_agent_identities
    FOR ALL USING (
        current_setting('chora.tenant_id', true) IS NULL
        OR current_setting('chora.tenant_id', true) = ''
        OR tenant_id = current_setting('chora.tenant_id', true)::uuid
    );

-- -----------------------------------------------------------------------------
-- Self-contained GRANTs (42501 lesson): 9999_grant_app_roles.sql already ran on
-- live DBs, so these two tables need their own grants. Idempotent (GRANT is a
-- no-op if already held via the migrate role's ALTER DEFAULT PRIVILEGES).
-- app_rw / app_ro have NO BYPASSRLS — the policies above still apply.
-- -----------------------------------------------------------------------------
GRANT SELECT, INSERT, UPDATE, DELETE ON byoa_keys, external_agent_identities
  TO chora_a2a_app_rw;
GRANT SELECT ON byoa_keys, external_agent_identities
  TO chora_a2a_app_ro;

COMMIT;
