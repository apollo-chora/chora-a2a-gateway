// partner_repository.go — pgx-backed implementation of partner persistence.
//
// SQL contract:
//
//   - Put: UPSERT on conflict(agid). agid is the primary key per ADR-132 +
//     migrations/0001_initial.sql.
//   - Get: returns ErrPartnerNotFound when missing or wrong tenant.
//
// Soft delete: queries filter `deleted_at IS NULL`. RLS: `partners` is
// tenant-scoped — the integration test wraps Put/Get in a transaction with
// `SET LOCAL chora.tenant_id`. The unit-test stub path doesn't enforce RLS
// (no live DB).
//
// AGID ≠ GCID: this file MUST NOT reference any gcid column. The migration
// already enforces this at the schema level (no gcid column in partners);
// the unit test asserts it at the SQL-string level for defence-in-depth.
package pg

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/partner"
)

// ErrPartnerNotFound is returned when a partner row is missing.
var ErrPartnerNotFound = errors.New("pg: partner not found")

// PartnerRepository is the pgx-backed partner persistence adapter.
type PartnerRepository struct {
	q Querier
}

// NewPartnerRepository wraps a Querier.
func NewPartnerRepository(q Querier) *PartnerRepository {
	return &PartnerRepository{q: q}
}

// Put upserts the partner under the supplied tenant. The Partner aggregate
// has no Tenant field (kept tenant-agnostic for testability); callers
// supply tenantID at the persistence boundary.
//
// Column order matches migrations/0001_initial.sql `partners`:
//
//	agid, tenant_id, org_name, contact_email, api_key_hash, status,
//	suspended_at, suspend_reason, rate_limit_per_min, quota_per_day,
//	allowed_scopes, created_at, updated_at, deleted_at
//
// SECURITY: `api_key_hash` is bound from the REAL credential hash carried on
// the aggregate (p.APIKeyHash) — the SHA-256 of the one-time plaintext minted
// at partner.Registration.Approve. It MUST NOT be derived from the public
// AGID: a public-derivable hash is forgeable by anyone who knows the AGID.
// A Partner reaching Put with an empty APIKeyHash is a programmer error
// (credential never minted / dropped before persistence) and is rejected
// loudly — we never write a blank or placeholder credential hash.
func (r *PartnerRepository) Put(ctx context.Context, tenantID string, p *partner.Partner) error {
	if p == nil {
		return errors.New("pg.PartnerRepository.Put: nil partner")
	}
	if strings.TrimSpace(tenantID) == "" {
		return errors.New("pg.PartnerRepository.Put: tenantID required")
	}
	if strings.TrimSpace(p.APIKeyHash) == "" {
		return fmt.Errorf("pg.PartnerRepository.Put: partner %q has empty APIKeyHash — refusing to persist a blank/forgeable credential hash", p.AGID)
	}

	q := `
        INSERT INTO partners (
            agid, tenant_id, org_name, contact_email, api_key_hash, status,
            suspended_at, suspend_reason,
            rate_limit_per_min, quota_per_day, allowed_scopes,
            created_at, updated_at, deleted_at
        )
        VALUES ($1, $2, $3, $4, $5, $6::partner_status,
                $7, $8,
                $9, $10, $11,
                $12, $13, $14)
        ON CONFLICT (agid) DO UPDATE SET
            org_name           = EXCLUDED.org_name,
            status             = EXCLUDED.status,
            suspended_at       = EXCLUDED.suspended_at,
            suspend_reason     = EXCLUDED.suspend_reason,
            rate_limit_per_min = EXCLUDED.rate_limit_per_min,
            quota_per_day      = EXCLUDED.quota_per_day,
            allowed_scopes     = EXCLUDED.allowed_scopes,
            updated_at         = EXCLUDED.updated_at,
            deleted_at         = EXCLUDED.deleted_at
    `
	return r.q.Exec(ctx, q,
		p.AGID,
		tenantID,
		p.Name,
		"",           // contact_email — populated by Registration in M14
		p.APIKeyHash, // api_key_hash — REAL approval-minted hash (never AGID-derived)
		string(p.Status),
		nullableTimePtr(p.SuspendedAt),
		nullableString(p.SuspendReason),
		p.RateLimitPerMin,
		p.QuotaPerDay,
		p.AllowedScopes,
		p.CreatedAt,
		p.UpdatedAt,
		nullableTimePtr(p.DeletedAt),
	)
}

// Get fetches the partner under (tenantID, agid). Returns
// ErrPartnerNotFound on miss.
func (r *PartnerRepository) Get(ctx context.Context, tenantID, agid string) (*partner.Partner, error) {
	q := `
        SELECT agid, org_name, api_key_hash, status,
               suspended_at, suspend_reason,
               rate_limit_per_min, quota_per_day, allowed_scopes,
               created_at, updated_at, deleted_at
        FROM partners
        WHERE tenant_id = $1 AND agid = $2 AND deleted_at IS NULL
    `
	row := r.q.QueryRow(ctx, q, tenantID, agid)

	var (
		p             partner.Partner
		status        string
		suspendedAt   *time.Time
		suspendReason *string
		deletedAt     *time.Time
		allowedScopes []string
	)
	err := row.Scan(
		&p.AGID,
		&p.Name,
		&p.APIKeyHash,
		&status,
		&suspendedAt,
		&suspendReason,
		&p.RateLimitPerMin,
		&p.QuotaPerDay,
		&allowedScopes,
		&p.CreatedAt,
		&p.UpdatedAt,
		&deletedAt,
	)
	if err != nil {
		if errors.Is(err, ErrNoRows) {
			return nil, ErrPartnerNotFound
		}
		return nil, fmt.Errorf("pg.PartnerRepository.Get: %w", err)
	}
	p.Status = partner.Status(status)
	p.AllowedScopes = allowedScopes
	if suspendedAt != nil {
		t := suspendedAt.UTC()
		p.SuspendedAt = &t
	}
	if suspendReason != nil {
		p.SuspendReason = *suspendReason
	}
	if deletedAt != nil {
		t := deletedAt.UTC()
		p.DeletedAt = &t
	}
	return &p, nil
}

func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullableTimePtr(t *time.Time) any {
	if t == nil {
		return nil
	}
	return *t
}
