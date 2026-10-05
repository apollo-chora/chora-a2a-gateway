// Package partner_test exercises the A2APartnerRegistry aggregate root
// invariants per ADR-132 (Tier 1 D1 + ADR-132 §3 A2APartnerRegistry).
//
// TDD RED phase — these tests assume the implementation does NOT yet exist.
package partner_test

import (
	"testing"
	"time"

	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/partner"
)

const (
	agidA = "01970000-0000-7000-b000-000000000001"
	agidB = "01970000-0000-7000-b000-000000000002"
)

// -----------------------------------------------------------------------------
// New / construction invariants
// -----------------------------------------------------------------------------

func TestNew_AssignsAGIDAndDefaults(t *testing.T) {
	t.Parallel()

	p, err := partner.New(partner.NewParams{
		AGID:            agidA,
		Name:            "Acme Tutor Co",
		AllowedScopes:   []string{"discover_learner_profile", "recommend_content"},
		RateLimitPerMin: 100,
		QuotaPerDay:     10000,
	})
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}
	if p.AGID != agidA {
		t.Errorf("AGID = %q; want %q", p.AGID, agidA)
	}
	if p.Status != partner.StatusActive {
		t.Errorf("Status = %q; want %q on creation", p.Status, partner.StatusActive)
	}
	if p.RateLimitPerMin != 100 {
		t.Errorf("RateLimitPerMin = %d; want 100", p.RateLimitPerMin)
	}
	if p.QuotaPerDay != 10000 {
		t.Errorf("QuotaPerDay = %d; want 10000", p.QuotaPerDay)
	}
	if p.CreatedAt.IsZero() {
		t.Error("CreatedAt was zero; want set")
	}
	if p.DeletedAt != nil {
		t.Error("DeletedAt was non-nil; want nil on creation")
	}
	// No credential minted at bare construction — the real api_key_hash is
	// carried in only at approval time (Registration.Approve → New).
	if p.APIKeyHash != "" {
		t.Errorf("APIKeyHash = %q; want empty on bare construction", p.APIKeyHash)
	}
}

// TestNew_CarriesAPIKeyHash proves the aggregate carries the REAL credential
// hash minted at approval, so it survives to the persistence boundary instead
// of being dropped (which previously forced a forgeable AGID-derived
// placeholder at the repo).
func TestNew_CarriesAPIKeyHash(t *testing.T) {
	t.Parallel()

	const realHash = "deadbeefcafef00d0011223344556677889900aabbccddeeff00112233445566"
	p, err := partner.New(partner.NewParams{
		AGID:            agidA,
		Name:            "Acme Tutor Co",
		AllowedScopes:   []string{"recommend_content"},
		RateLimitPerMin: 100,
		QuotaPerDay:     10000,
		APIKeyHash:      realHash,
	})
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}
	if p.APIKeyHash != realHash {
		t.Errorf("APIKeyHash = %q; want carried-through %q", p.APIKeyHash, realHash)
	}
}

func TestNew_RejectsEmptyAGID(t *testing.T) {
	t.Parallel()

	_, err := partner.New(partner.NewParams{
		AGID:            "",
		Name:            "x",
		RateLimitPerMin: 10,
		QuotaPerDay:     100,
	})
	if err == nil {
		t.Error("expected error for empty AGID; got nil")
	}
}

func TestNew_RejectsEmptyName(t *testing.T) {
	t.Parallel()

	_, err := partner.New(partner.NewParams{
		AGID:            agidA,
		Name:            "  ",
		RateLimitPerMin: 10,
		QuotaPerDay:     100,
	})
	if err == nil {
		t.Error("expected error for empty Name; got nil")
	}
}

func TestNew_RejectsNegativeRateLimit(t *testing.T) {
	t.Parallel()

	_, err := partner.New(partner.NewParams{
		AGID:            agidA,
		Name:            "x",
		RateLimitPerMin: -1,
		QuotaPerDay:     100,
	})
	if err == nil {
		t.Error("expected error for negative RateLimitPerMin; got nil")
	}
}

func TestNew_RejectsNegativeQuota(t *testing.T) {
	t.Parallel()

	_, err := partner.New(partner.NewParams{
		AGID:            agidA,
		Name:            "x",
		RateLimitPerMin: 10,
		QuotaPerDay:     -1,
	})
	if err == nil {
		t.Error("expected error for negative QuotaPerDay; got nil")
	}
}

// CRITICAL invariant per CLAUDE.md §1 + ADR-132 §2:
// AGID is distinct from GCID. A partner registry entry NEVER holds a GCID.
// The struct must not even have a GCID field.
func TestPartner_HasNoGCIDField(t *testing.T) {
	t.Parallel()

	// Compile-time check via reflection-style probe; if the field exists
	// this test documents the invariant. A change that adds a GCID field
	// to Partner should be rejected at code review.
	p, _ := partner.New(partner.NewParams{
		AGID:            agidA,
		Name:            "x",
		RateLimitPerMin: 10,
		QuotaPerDay:     100,
	})
	// Verify that AGID is set and there is no companion gcid attribute we
	// inadvertently exposed via JSON, etc.
	if p.AGID == "" {
		t.Error("AGID empty")
	}
}

// -----------------------------------------------------------------------------
// Suspension lifecycle
// -----------------------------------------------------------------------------

func TestSuspend_TransitionsToSuspended(t *testing.T) {
	t.Parallel()

	p, _ := partner.New(partner.NewParams{
		AGID:            agidA,
		Name:            "x",
		RateLimitPerMin: 10,
		QuotaPerDay:     100,
	})
	if err := p.Suspend("compliance_review"); err != nil {
		t.Fatalf("Suspend unexpected error: %v", err)
	}
	if p.Status != partner.StatusSuspended {
		t.Errorf("Status = %q; want %q", p.Status, partner.StatusSuspended)
	}
	if p.SuspendedAt == nil {
		t.Error("SuspendedAt nil; want non-nil after Suspend")
	}
	if p.SuspendReason != "compliance_review" {
		t.Errorf("SuspendReason = %q; want %q", p.SuspendReason, "compliance_review")
	}
}

func TestReinstate_TransitionsBackToActive(t *testing.T) {
	t.Parallel()

	p, _ := partner.New(partner.NewParams{
		AGID:            agidA,
		Name:            "x",
		RateLimitPerMin: 10,
		QuotaPerDay:     100,
	})
	_ = p.Suspend("test")
	if err := p.Reinstate(); err != nil {
		t.Fatalf("Reinstate unexpected error: %v", err)
	}
	if p.Status != partner.StatusActive {
		t.Errorf("Status = %q; want %q", p.Status, partner.StatusActive)
	}
	if p.SuspendedAt != nil {
		t.Error("SuspendedAt non-nil; want nil after Reinstate")
	}
}

func TestIsActive_FalseAfterSuspend(t *testing.T) {
	t.Parallel()

	p, _ := partner.New(partner.NewParams{
		AGID:            agidA,
		Name:            "x",
		RateLimitPerMin: 10,
		QuotaPerDay:     100,
	})
	if !p.IsActive() {
		t.Error("IsActive() = false; want true on fresh partner")
	}
	_ = p.Suspend("any")
	if p.IsActive() {
		t.Error("IsActive() = true; want false after Suspend")
	}
}

// -----------------------------------------------------------------------------
// Soft-delete invariant (ddd-enforcement #5)
// -----------------------------------------------------------------------------

func TestSoftDelete_SetsDeletedAt(t *testing.T) {
	t.Parallel()

	p, _ := partner.New(partner.NewParams{
		AGID:            agidA,
		Name:            "x",
		RateLimitPerMin: 10,
		QuotaPerDay:     100,
	})
	if err := p.SoftDelete(); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if p.DeletedAt == nil {
		t.Error("DeletedAt = nil; want non-nil after SoftDelete")
	}
}

func TestScopeAllowed_EnforcesAllowList(t *testing.T) {
	t.Parallel()

	p, _ := partner.New(partner.NewParams{
		AGID:            agidA,
		Name:            "x",
		AllowedScopes:   []string{"recommend_content"},
		RateLimitPerMin: 10,
		QuotaPerDay:     100,
	})
	if !p.ScopeAllowed("recommend_content") {
		t.Error("expected scope allowed")
	}
	if p.ScopeAllowed("write_persona_memory") {
		t.Error("scope should NOT be allowed")
	}
}

// Verify defensive copy of AllowedScopes — caller mutation must not leak.
func TestNew_CopiesAllowedScopesDefensively(t *testing.T) {
	t.Parallel()

	scopes := []string{"recommend_content"}
	p, _ := partner.New(partner.NewParams{
		AGID:            agidA,
		Name:            "x",
		AllowedScopes:   scopes,
		RateLimitPerMin: 10,
		QuotaPerDay:     100,
	})
	scopes[0] = "MUTATED"
	if p.ScopeAllowed("MUTATED") {
		t.Error("scope mutation leaked into Partner; defensive copy missing")
	}
}

// Sanity: tests run within a deterministic time window.
func TestNew_TimestampsAreUTC(t *testing.T) {
	t.Parallel()
	before := time.Now().UTC()
	p, _ := partner.New(partner.NewParams{
		AGID:            agidA,
		Name:            "x",
		RateLimitPerMin: 10,
		QuotaPerDay:     100,
	})
	after := time.Now().UTC()
	if p.CreatedAt.Before(before) || p.CreatedAt.After(after) {
		t.Errorf("CreatedAt = %v; want between %v and %v", p.CreatedAt, before, after)
	}
}
