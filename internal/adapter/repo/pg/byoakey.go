// byoakey.go — pgx-backed implementation of the repo.BYOAKeyStore port
// (W0-F1, CHO-2198). Closes the "BYOA partner API-key hashes wiped on pod
// restart" durability gap: BYOAKeyRepo (internal/adapter/repo/inmem) held every
// registered external-LLM provider key in a plain Go map with no persistence
// across a rollout — AUTH state evaporating on every restart.
//
// Architecture notes (mirrors mcpconfig.go exactly):
//
//   - Reuses the local pg.Querier interface from
//     internal/adapter/pg/runtime.go so unit tests stub the SQL surface
//     without a live Postgres connection.
//   - Keyed by the (tenant_id, provider) natural key — Put/Get/SoftDelete all
//     take the tenant per call (NOT a construction-bound tenant), because one
//     store serves every tenant's keys, exactly like MCPConfigStore.
//   - Tenant scoping: the byoa_keys RLS policy (migrations/0009) falls through
//     to permissive when chora.tenant_id is unset, which is the CURRENT reality
//     for every pg query this service issues (runtime.go's PgxPoolQuerier
//     issues bare pool.Exec/Query, no `SET LOCAL` wrapper). Isolation is
//     enforced today by the bound `tenant_id = $1` parameter, identical to
//     RegistrationStore / MCPConfigStore. Once SET LOCAL chora.tenant_id lands
//     the policy enforces for free.
//   - Soft-delete: Get filters `deleted_at IS NULL`; SoftDelete tombstones.
//   - AGID ≠ GCID (CLAUDE.md §1): NO gcid column — the unit test asserts it at
//     the SQL-string level for defence-in-depth.
package pg

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	chorapg "github.com/apollo-chora/chora-a2a-gateway/internal/adapter/pg"
	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/repo"
)

// BYOAKeyStore is the pgx-backed implementation of the repo.BYOAKeyStore port.
type BYOAKeyStore struct {
	q chorapg.Querier
}

// NewBYOAKeyStore wraps a Querier. No tenantID is bound at construction —
// BYOA keys are keyed BY (tenant, provider) per call, mirroring MCPConfigStore.
func NewBYOAKeyStore(q chorapg.Querier) *BYOAKeyStore {
	return &BYOAKeyStore{q: q}
}

// Put upserts the encrypted BYOA key for (tenant_id, provider). A re-registration
// (rotation) replaces the ciphertext + fingerprint and clears any prior
// tombstone (deleted_at → NULL), matching inmem.BYOAKeyRepo.Put's full-replace
// semantics.
//
// SECURITY: a vault row MUST carry both a real ciphertext AND its fingerprint —
// an entry reaching Put with an empty Ciphertext or KeyFingerprint is a
// programmer error (credential dropped before persistence) and is rejected
// loudly, mirroring partner_repository.go / mcpconfig.go's empty-hash guard.
// We never write a blank/placeholder credential.
func (r *BYOAKeyStore) Put(e *repo.BYOAKeyEntry) error {
	if e == nil {
		return errors.New("pg.BYOAKeyStore.Put: nil entry")
	}
	if strings.TrimSpace(e.TenantID) == "" {
		return errors.New("pg.BYOAKeyStore.Put: TenantID required")
	}
	if strings.TrimSpace(e.Provider) == "" {
		return errors.New("pg.BYOAKeyStore.Put: Provider required")
	}
	if strings.TrimSpace(e.KeyFingerprint) == "" {
		return fmt.Errorf("pg.BYOAKeyStore.Put: tenant %q provider %q has empty KeyFingerprint — refusing to persist a blank credential", e.TenantID, e.Provider)
	}
	if len(e.Ciphertext) == 0 {
		return fmt.Errorf("pg.BYOAKeyStore.Put: tenant %q provider %q has empty Ciphertext — refusing to persist a keyless BYOA vault row", e.TenantID, e.Provider)
	}
	const q = `
INSERT INTO byoa_keys (
    tenant_id, provider, ciphertext, key_fingerprint, rotated_at, deleted_at
) VALUES (
    $1, $2, $3, $4, $5, $6
)
ON CONFLICT (tenant_id, provider) DO UPDATE SET
    ciphertext      = EXCLUDED.ciphertext,
    key_fingerprint = EXCLUDED.key_fingerprint,
    rotated_at      = EXCLUDED.rotated_at,
    deleted_at      = EXCLUDED.deleted_at
`
	return r.q.Exec(context.Background(), q,
		e.TenantID,
		e.Provider,
		e.Ciphertext,
		e.KeyFingerprint,
		e.RotatedAt,
		nullableTimePtr(e.DeletedAt),
	)
}

const byoaKeySelectColumns = `
    tenant_id, provider, ciphertext, key_fingerprint, rotated_at, deleted_at
`

// Get fetches the live (non-revoked) key for (tenant_id, provider). Returns
// repo.ErrNotFound on miss.
func (r *BYOAKeyStore) Get(tenantID, provider string) (*repo.BYOAKeyEntry, error) {
	q := `SELECT ` + byoaKeySelectColumns + `
FROM byoa_keys
WHERE tenant_id = $1 AND provider = $2 AND deleted_at IS NULL
`
	row := r.q.QueryRow(context.Background(), q, tenantID, provider)
	return scanBYOAKey(row)
}

// SoftDelete tombstones the live key for (tenant_id, provider) — BYOA key
// revocation. Get-then-UPDATE (mirrors MCPConfigStore.SetSuspended): the shared
// Querier.Exec returns no rows-affected, so an existence check precedes the
// tombstone. An absent OR already-revoked key returns repo.ErrNotFound — the
// ext_router DELETE handler maps that to 404.
func (r *BYOAKeyStore) SoftDelete(tenantID, provider string) error {
	if _, err := r.Get(tenantID, provider); err != nil {
		return err
	}
	const q = `
UPDATE byoa_keys
SET deleted_at = now()
WHERE tenant_id = $1 AND provider = $2 AND deleted_at IS NULL
`
	return r.q.Exec(context.Background(), q, tenantID, provider)
}

func scanBYOAKey(row chorapg.Row) (*repo.BYOAKeyEntry, error) {
	var (
		e         repo.BYOAKeyEntry
		deletedAt *time.Time
	)
	err := row.Scan(
		&e.TenantID,
		&e.Provider,
		&e.Ciphertext,
		&e.KeyFingerprint,
		&e.RotatedAt,
		&deletedAt,
	)
	if err != nil {
		if errors.Is(err, chorapg.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("pg.BYOAKeyStore.scan: %w", err)
	}
	e.RotatedAt = e.RotatedAt.UTC()
	if deletedAt != nil {
		t := deletedAt.UTC()
		e.DeletedAt = &t
	}
	return &e, nil
}
