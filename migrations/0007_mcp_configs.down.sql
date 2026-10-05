-- =============================================================================
-- chora-a2a-gateway : 0007_mcp_configs.down.sql
--
-- Reverses 0007_mcp_configs.up.sql.
-- =============================================================================

BEGIN;

DROP TRIGGER IF EXISTS trg_mcp_configs_updated_at ON mcp_configs;
DROP TABLE IF EXISTS mcp_configs;

COMMIT;
