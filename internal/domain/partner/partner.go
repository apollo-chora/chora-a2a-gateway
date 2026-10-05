// Package partner implements the A2APartnerRegistry aggregate root per
// ADR-132 §3 (Tier 1 D1 — Agent-to-Agent core domain).
//
// A Partner represents a registered external partner agent that may invoke
// Chora-side capabilities. Partners are addressed by their AGID (UUIDv7) —
// AGID is DISTINCT from GCID (CLAUDE.md §1) and a Partner aggregate must
// NEVER hold a GCID. Agents cannot hold TenantMembership.
//
// Aggregate invariants enforced here:
//   - AGID required, non-empty
//   - Name required, trimmed, non-empty
//   - RateLimitPerMin / QuotaPerDay non-negative
//   - Lifecycle: Active <-> Suspended; SoftDelete is terminal-soft
//   - AllowedScopes copied defensively on construction
package partner

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Status is the partner lifecycle state.
type Status string

const (
	StatusActive    Status = "active"
	StatusSuspended Status = "suspended"
)

// Partner is the aggregate root.
//
// NOTE: there is intentionally NO Gcid field — agents do not hold GCIDs.
type Partner struct {
	AGID            string
	Name            string
	AllowedScopes   []string
	RateLimitPerMin int
	QuotaPerDay     int
	Status          Status
	SuspendedAt     *time.Time
	SuspendReason   string
	CreatedAt       time.Time
	UpdatedAt       time.Time
	DeletedAt       *time.Time

	// APIKeyHash is the SHA-256 hex digest of the partner's API key, minted
	// ONCE at Registration.Approve (the one-time plaintext is returned to the
	// partner there and NEVER persisted). It is carried on the aggregate so
	// the real credential hash survives to the persistence boundary — the
	// repo MUST bind this value, never a placeholder derivable from the
	// public AGID. Empty at bare construction (no credential minted yet).
	APIKeyHash string
}

// NewParams is the input shape for New.
type NewParams struct {
	AGID            string
	Name            string
	AllowedScopes   []string
	RateLimitPerMin int
	QuotaPerDay     int

	// APIKeyHash is optional at construction. It carries the real
	// approval-minted credential hash through to persistence; it stays empty
	// for partners constructed before a credential is minted.
	APIKeyHash string
}

// New constructs a fresh Partner enforcing aggregate invariants.
func New(p NewParams) (*Partner, error) {
	if strings.TrimSpace(p.AGID) == "" {
		return nil, errors.New("partner: AGID required")
	}
	name := strings.TrimSpace(p.Name)
	if name == "" {
		return nil, errors.New("partner: Name required")
	}
	if p.RateLimitPerMin < 0 {
		return nil, fmt.Errorf("partner: RateLimitPerMin must be >= 0, got %d", p.RateLimitPerMin)
	}
	if p.QuotaPerDay < 0 {
		return nil, fmt.Errorf("partner: QuotaPerDay must be >= 0, got %d", p.QuotaPerDay)
	}

	scopes := make([]string, len(p.AllowedScopes))
	copy(scopes, p.AllowedScopes)

	now := time.Now().UTC()
	return &Partner{
		AGID:            p.AGID,
		Name:            name,
		AllowedScopes:   scopes,
		RateLimitPerMin: p.RateLimitPerMin,
		QuotaPerDay:     p.QuotaPerDay,
		Status:          StatusActive,
		APIKeyHash:      p.APIKeyHash,
		CreatedAt:       now,
		UpdatedAt:       now,
	}, nil
}

// Suspend transitions the partner to Suspended status. All A2A calls
// will be rejected with 403 while suspended.
func (p *Partner) Suspend(reason string) error {
	if p.DeletedAt != nil {
		return errors.New("partner: cannot suspend a soft-deleted partner")
	}
	now := time.Now().UTC()
	p.Status = StatusSuspended
	p.SuspendedAt = &now
	p.SuspendReason = reason
	p.UpdatedAt = now
	return nil
}

// Reinstate moves the partner back to Active.
func (p *Partner) Reinstate() error {
	if p.DeletedAt != nil {
		return errors.New("partner: cannot reinstate a soft-deleted partner")
	}
	p.Status = StatusActive
	p.SuspendedAt = nil
	p.SuspendReason = ""
	p.UpdatedAt = time.Now().UTC()
	return nil
}

// SoftDelete marks the partner as deleted (ddd-enforcement #5).
// Hard delete is reserved for crypto-shred.
func (p *Partner) SoftDelete() error {
	now := time.Now().UTC()
	p.DeletedAt = &now
	p.UpdatedAt = now
	return nil
}

// IsActive reports whether the partner is currently allowed to invoke.
// (Active status, not suspended, not soft-deleted.)
func (p *Partner) IsActive() bool {
	return p.Status == StatusActive && p.DeletedAt == nil
}

// ScopeAllowed reports whether the given scope is in the partner's
// allow-list.
func (p *Partner) ScopeAllowed(scope string) bool {
	for _, s := range p.AllowedScopes {
		if s == scope {
			return true
		}
	}
	return false
}
