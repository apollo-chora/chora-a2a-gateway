-- =============================================================================
-- chora-a2a-gateway : 0006_oplus_repos.down.sql
--
-- Reverses 0006_oplus_repos.up.sql — drops the three M12-backlog tables
-- and their enums.
-- =============================================================================

BEGIN;

DROP TRIGGER IF EXISTS trg_a2a_invocations_no_delete         ON a2a_invocations;
DROP TRIGGER IF EXISTS trg_a2a_invocations_immutable_update  ON a2a_invocations;
DROP FUNCTION IF EXISTS enforce_a2a_invocations_append_only();

DROP TRIGGER IF EXISTS trg_a2a_contracts_updated_at          ON a2a_contracts;
DROP TRIGGER IF EXISTS trg_partner_registrations_updated_at  ON partner_registrations;

DROP TABLE IF EXISTS a2a_invocations;
DROP TABLE IF EXISTS a2a_contracts;
DROP TABLE IF EXISTS partner_registrations;

DROP TYPE IF EXISTS a2a_invocation_status;
DROP TYPE IF EXISTS a2a_contract_auth;
DROP TYPE IF EXISTS registration_tier;
DROP TYPE IF EXISTS registration_state;

COMMIT;
