-- =============================================================================
-- chora-a2a-gateway : 0009_auth_state_durability.down.sql
--
-- Reverses 0009_auth_state_durability.up.sql. Drops the two AUTH-state tables
-- (their policies, triggers, and indexes drop with them). CASCADE guards
-- against any dependent object; there are no FKs into these tables.
--
-- NB: this is a DROP TABLE — the migration-tracker apply lane REFUSES
-- destructive DDL, so this .down.sql is documentation / manual-rollback only,
-- never auto-applied. Data loss on down is acceptable: these tables hold
-- re-derivable AUTH state (re-registered via /admin/byoa + key upload).
-- =============================================================================

BEGIN;

DROP TABLE IF EXISTS external_agent_identities CASCADE;
DROP TABLE IF EXISTS byoa_keys CASCADE;

COMMIT;
