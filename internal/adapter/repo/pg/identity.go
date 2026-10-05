// identity.go — pgx-backed implementation of the repo.IdentityStore port
// (W0-F1, CHO-2198). Closes the "ExternalAgentIdentity public keys wiped on pod
// restart" durability gap: the legacy internal/adapter/inmem.IdentityStore held
// every registered partner public-key PEM + fingerprint in a plain Go map with
// no persistence across a rollout — AUTH/identity state the O+ A2A console
// reads, evaporating on every restart.
//
// Architecture notes (mirrors RegistrationStore in repo.go):
//
//   - Reuses the local pg.Querier interface from
//     internal/adapter/pg/runtime.go so unit tests stub the SQL surface.
//   - Tenant bound at construction (NewIdentityStore(q, tenantID)) exactly like
//     RegistrationStore / ContractStore / InvocationStore — the O+ read path
//     lists ONE env-bound tenant's registrations (CHORA_A2A_REPO_TENANT_ID) and
//     their identities, so no tenant flows through the method signatures. The
//     bound tenant is the `tenant_id = $1` bind (RLS defence-in-depth; the
//     byoa/identity RLS policies fall through to permissive when
//     chora.tenant_id is unset, the current pg reality).
//   - Soft-delete: Get filters `deleted_at IS NULL`. ExternalAgentIdentity has
//     no lifecycle tombstone of its own (agents have no closure saga —
//     ddd-enforcement #10); the deleted_at column exists for schema-consistency
//     and the closure saga's admin-display tokenisation (PII_Closure_Map.yaml).
//   - AGID ≠ GCID (CLAUDE.md §1): NO gcid column — the unit test asserts it at
//     the SQL-string level for defence-in-depth.
package pg

import (
	"context"
	"errors"
	"fmt"
	"strings"

	chorapg "github.com/apollo-chora/chora-a2a-gateway/internal/adapter/pg"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/agent_identity"
)

// IdentityStore is the pgx-backed implementation of the repo.IdentityStore port.
type IdentityStore struct {
	q        chorapg.Querier
	tenantID string
}

// NewIdentityStore wraps a Querier with a tenant binding (mirrors
// NewRegistrationStore).
func NewIdentityStore(q chorapg.Querier, tenantID string) *IdentityStore {
	return &IdentityStore{q: q, tenantID: tenantID}
}

// Put upserts the ExternalAgentIdentity keyed on its AGID. A Rotate replaces
// the PEM + fingerprint and clears any tombstone, matching inmem.IdentityStore's
// map-replace semantics.
//
// SECURITY: an identity MUST carry a real public-key PEM — one reaching Put with
// an empty PublicKeyPEM is a programmer error and is rejected loudly (never a
// blank/placeholder key), mirroring the sibling durable adapters' credential
// guards.
func (r *IdentityStore) Put(id *agent_identity.ExternalAgentIdentity) error {
	if id == nil {
		return errors.New("pg.IdentityStore.Put: nil identity")
	}
	if strings.TrimSpace(id.AGID) == "" {
		return errors.New("pg.IdentityStore.Put: AGID required")
	}
	if strings.TrimSpace(id.PublicKeyPEM) == "" {
		return fmt.Errorf("pg.IdentityStore.Put: agid %q has empty PublicKeyPEM — refusing to persist a keyless identity", id.AGID)
	}
	const q = `
INSERT INTO external_agent_identities (
    agid, tenant_id, public_key_pem, key_fingerprint, jwks_uri, algorithm,
    created_at, updated_at, deleted_at
) VALUES (
    $1, $2, $3, $4, $5, $6,
    $7, $8, $9
)
ON CONFLICT (agid) DO UPDATE SET
    public_key_pem  = EXCLUDED.public_key_pem,
    key_fingerprint = EXCLUDED.key_fingerprint,
    jwks_uri        = EXCLUDED.jwks_uri,
    algorithm       = EXCLUDED.algorithm,
    updated_at      = EXCLUDED.updated_at,
    deleted_at      = EXCLUDED.deleted_at
`
	return r.q.Exec(context.Background(), q,
		id.AGID,
		r.tenantID,
		id.PublicKeyPEM,
		id.KeyFingerprint,
		id.JWKSURI,
		string(id.Algorithm),
		id.CreatedAt,
		id.UpdatedAt,
		nil, // deleted_at — ExternalAgentIdentity carries no tombstone (agents have no closure saga); a re-Put clears any prior one.
	)
}

const identitySelectColumns = `
    agid, public_key_pem, key_fingerprint, jwks_uri, algorithm,
    created_at, updated_at
`

// Get fetches the live (non-tombstoned) identity for the AGID under the bound
// tenant. Returns repo.ErrNotFound on miss (including when no key has been
// uploaded for the AGID yet — the O+ listing then emits an empty fingerprint).
func (r *IdentityStore) Get(agid string) (*agent_identity.ExternalAgentIdentity, error) {
	q := `SELECT ` + identitySelectColumns + `
FROM external_agent_identities
WHERE tenant_id = $1 AND agid = $2 AND deleted_at IS NULL
`
	row := r.q.QueryRow(context.Background(), q, r.tenantID, agid)
	return scanIdentity(row)
}

func scanIdentity(row chorapg.Row) (*agent_identity.ExternalAgentIdentity, error) {
	var (
		id  agent_identity.ExternalAgentIdentity
		alg string
	)
	err := row.Scan(
		&id.AGID,
		&id.PublicKeyPEM,
		&id.KeyFingerprint,
		&id.JWKSURI,
		&alg,
		&id.CreatedAt,
		&id.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, chorapg.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("pg.IdentityStore.scan: %w", err)
	}
	id.Algorithm = agent_identity.Algorithm(alg)
	id.CreatedAt = id.CreatedAt.UTC()
	id.UpdatedAt = id.UpdatedAt.UTC()
	return &id, nil
}
