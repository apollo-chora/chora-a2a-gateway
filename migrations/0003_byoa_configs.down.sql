-- DOWN: drop byoa_configs and its enum (relocated 2026-05-12 from chora-familiar 018).
BEGIN;
DROP POLICY IF EXISTS tenant_isolation ON byoa_configs;
DROP TRIGGER IF EXISTS trg_byoa_configs_updated_at ON byoa_configs;
DROP TABLE IF EXISTS byoa_configs;
DROP TYPE IF EXISTS byoa_provider;
COMMIT;
