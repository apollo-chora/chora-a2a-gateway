// Package contract_test exercises the A2AContract aggregate root invariants.
//
// Per ADR-132 §3 + task spec: a Contract declares the capabilities a partner
// may invoke + per-capability rate limits + auth method. Contract validation:
// capability not in list → 403; rate exceeded → 429.
//
// CRITICAL invariants:
//   - PartnerID required; non-empty
//   - At least one capability required
//   - Capability has rate-limit per minute (>= 1) + tier
//   - Auth method enum (api_key | jws_ed25519 | oauth2)
//   - HasCapability returns false for non-listed capability
//   - RateLimitFor returns the per-capability config; not-found returns 0
//
// TDD RED phase — implementation does NOT yet exist.
package contract_test

import (
	"testing"

	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/contract"
)

const (
	contractA = "01970000-0000-7000-d000-000000000001"
	partnerA  = "01970000-0000-7000-a000-000000000001"
)

func TestNewContract_AssignsCapabilities(t *testing.T) {
	t.Parallel()
	c, err := contract.New(contract.NewParams{
		ID:         contractA,
		PartnerID:  partnerA,
		AuthMethod: contract.AuthAPIKey,
		Capabilities: []contract.Capability{
			{Name: "recommend_content", Tier: contract.TierMedium, RateLimitPerMin: 60},
			{Name: "discover_learner_profile", Tier: contract.TierLow, RateLimitPerMin: 30},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.PartnerID != partnerA {
		t.Errorf("PartnerID = %q", c.PartnerID)
	}
	if c.AuthMethod != contract.AuthAPIKey {
		t.Errorf("AuthMethod = %q", c.AuthMethod)
	}
	if !c.HasCapability("recommend_content") {
		t.Error("HasCapability(recommend_content) = false; want true")
	}
	if c.HasCapability("write_persona_memory") {
		t.Error("HasCapability(write_persona_memory) = true; want false")
	}
}

func TestNewContract_RejectsEmptyPartnerID(t *testing.T) {
	t.Parallel()
	_, err := contract.New(contract.NewParams{
		ID:         contractA,
		PartnerID:  "",
		AuthMethod: contract.AuthAPIKey,
		Capabilities: []contract.Capability{
			{Name: "x", Tier: contract.TierLow, RateLimitPerMin: 10},
		},
	})
	if err == nil {
		t.Error("expected error for empty PartnerID; got nil")
	}
}

func TestNewContract_RejectsEmptyCapabilityList(t *testing.T) {
	t.Parallel()
	_, err := contract.New(contract.NewParams{
		ID:           contractA,
		PartnerID:    partnerA,
		AuthMethod:   contract.AuthAPIKey,
		Capabilities: nil,
	})
	if err == nil {
		t.Error("expected error for empty Capabilities; got nil")
	}
}

func TestNewContract_RejectsZeroRateLimit(t *testing.T) {
	t.Parallel()
	_, err := contract.New(contract.NewParams{
		ID:         contractA,
		PartnerID:  partnerA,
		AuthMethod: contract.AuthAPIKey,
		Capabilities: []contract.Capability{
			{Name: "x", Tier: contract.TierLow, RateLimitPerMin: 0},
		},
	})
	if err == nil {
		t.Error("expected error for zero rate limit; got nil")
	}
}

func TestNewContract_RejectsInvalidAuthMethod(t *testing.T) {
	t.Parallel()
	_, err := contract.New(contract.NewParams{
		ID:         contractA,
		PartnerID:  partnerA,
		AuthMethod: contract.AuthMethod("bogus"),
		Capabilities: []contract.Capability{
			{Name: "x", Tier: contract.TierLow, RateLimitPerMin: 10},
		},
	})
	if err == nil {
		t.Error("expected error for invalid auth method; got nil")
	}
}

func TestNewContract_RejectsInvalidTier(t *testing.T) {
	t.Parallel()
	_, err := contract.New(contract.NewParams{
		ID:         contractA,
		PartnerID:  partnerA,
		AuthMethod: contract.AuthAPIKey,
		Capabilities: []contract.Capability{
			{Name: "x", Tier: contract.Tier("bogus"), RateLimitPerMin: 10},
		},
	})
	if err == nil {
		t.Error("expected error for invalid tier; got nil")
	}
}

func TestRateLimitFor_FindsCapability(t *testing.T) {
	t.Parallel()
	c, _ := contract.New(contract.NewParams{
		ID:         contractA,
		PartnerID:  partnerA,
		AuthMethod: contract.AuthAPIKey,
		Capabilities: []contract.Capability{
			{Name: "recommend", Tier: contract.TierLow, RateLimitPerMin: 60},
			{Name: "discover", Tier: contract.TierMedium, RateLimitPerMin: 30},
		},
	})
	if got := c.RateLimitFor("recommend"); got != 60 {
		t.Errorf("RateLimitFor(recommend) = %d; want 60", got)
	}
	if got := c.RateLimitFor("discover"); got != 30 {
		t.Errorf("RateLimitFor(discover) = %d; want 30", got)
	}
	if got := c.RateLimitFor("nope"); got != 0 {
		t.Errorf("RateLimitFor(nope) = %d; want 0", got)
	}
}

func TestTierRateLimit_DefaultsByTier(t *testing.T) {
	t.Parallel()
	// Tier defaults provide a sensible per-tier max even when a contract
	// specifies a higher value (skeleton enforcement).
	tests := []struct {
		tier contract.Tier
		min  int // a sensible lower bound for defaults
	}{
		{contract.TierLow, 1},
		{contract.TierMedium, 1},
		{contract.TierHigh, 1},
		{contract.TierCritical, 1},
	}
	for _, tt := range tests {
		got := contract.TierMaxRateLimit(tt.tier)
		if got < tt.min {
			t.Errorf("TierMaxRateLimit(%s) = %d; want >= %d", tt.tier, got, tt.min)
		}
	}
}

func TestSoftDelete_SetsDeletedAt(t *testing.T) {
	t.Parallel()
	c, _ := contract.New(contract.NewParams{
		ID:         contractA,
		PartnerID:  partnerA,
		AuthMethod: contract.AuthAPIKey,
		Capabilities: []contract.Capability{
			{Name: "x", Tier: contract.TierLow, RateLimitPerMin: 10},
		},
	})
	if c.DeletedAt != nil {
		t.Error("fresh contract has DeletedAt set")
	}
	c.SoftDelete()
	if c.DeletedAt == nil {
		t.Error("after SoftDelete, DeletedAt should be set")
	}
}
