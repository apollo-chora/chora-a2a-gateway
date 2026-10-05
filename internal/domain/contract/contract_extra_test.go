// Package contract_test — extra tests covering contract versioning
// (Supersede), TierFor, IsActive, and HasCapability with soft-delete.
package contract_test

import (
	"testing"
	"time"

	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/contract"
)

func TestContract_TierFor(t *testing.T) {
	t.Parallel()
	c, _ := contract.New(contract.NewParams{
		ID: contractA, PartnerID: partnerA, AuthMethod: contract.AuthAPIKey,
		Capabilities: []contract.Capability{
			{Name: "rec", Tier: contract.TierHigh, RateLimitPerMin: 600},
		},
	})
	if got := c.TierFor("rec"); got != contract.TierHigh {
		t.Errorf("TierFor(rec) = %q; want high", got)
	}
	if got := c.TierFor("nope"); got != "" {
		t.Errorf("TierFor(nope) = %q; want empty", got)
	}
}

func TestContract_IsActive(t *testing.T) {
	t.Parallel()
	c, _ := contract.New(contract.NewParams{
		ID: contractA, PartnerID: partnerA, AuthMethod: contract.AuthAPIKey,
		Capabilities: []contract.Capability{
			{Name: "x", Tier: contract.TierLow, RateLimitPerMin: 10},
		},
	})
	if !c.IsActive() {
		t.Error("fresh contract not active")
	}
	c.SoftDelete()
	if c.IsActive() {
		t.Error("soft-deleted contract reports active")
	}

	// Sunset in the past.
	c2, _ := contract.New(contract.NewParams{
		ID:        "01970000-0000-7000-d000-000000000077",
		PartnerID: partnerA, AuthMethod: contract.AuthAPIKey,
		Capabilities: []contract.Capability{
			{Name: "x", Tier: contract.TierLow, RateLimitPerMin: 10},
		},
	})
	past := time.Now().UTC().Add(-time.Hour)
	c2.SunsetAt = &past
	if c2.IsActive() {
		t.Error("sunset contract reports active")
	}

	// Sunset in the future is OK.
	c3, _ := contract.New(contract.NewParams{
		ID:        "01970000-0000-7000-d000-000000000078",
		PartnerID: partnerA, AuthMethod: contract.AuthAPIKey,
		Capabilities: []contract.Capability{
			{Name: "x", Tier: contract.TierLow, RateLimitPerMin: 10},
		},
	})
	future := time.Now().UTC().Add(time.Hour)
	c3.SunsetAt = &future
	if !c3.IsActive() {
		t.Error("future-sunset contract not active")
	}
}

func TestContract_HasCapability_SoftDeleted(t *testing.T) {
	t.Parallel()
	c, _ := contract.New(contract.NewParams{
		ID: contractA, PartnerID: partnerA, AuthMethod: contract.AuthAPIKey,
		Capabilities: []contract.Capability{
			{Name: "x", Tier: contract.TierLow, RateLimitPerMin: 10},
		},
	})
	c.SoftDelete()
	if c.HasCapability("x") {
		t.Error("HasCapability returns true for soft-deleted contract")
	}
}

func TestContract_Supersede(t *testing.T) {
	t.Parallel()
	c, _ := contract.New(contract.NewParams{
		ID: contractA, PartnerID: partnerA, AuthMethod: contract.AuthAPIKey,
		Capabilities: []contract.Capability{
			{Name: "x", Tier: contract.TierLow, RateLimitPerMin: 10},
		},
	})
	v2, err := c.Supersede(contract.SupersedeParams{
		NewID:      "01970000-0000-7000-d000-000000000099",
		AuthMethod: contract.AuthJWSEd25519,
		Capabilities: []contract.Capability{
			{Name: "x", Tier: contract.TierMedium, RateLimitPerMin: 60},
			{Name: "y", Tier: contract.TierHigh, RateLimitPerMin: 600},
		},
		SunsetAfter: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Supersede: %v", err)
	}
	if v2.Version != 2 {
		t.Errorf("Version = %d; want 2", v2.Version)
	}
	if v2.SupersedesID != c.ID {
		t.Errorf("SupersedesID = %q", v2.SupersedesID)
	}
	if v2.AuthMethod != contract.AuthJWSEd25519 {
		t.Errorf("AuthMethod = %q", v2.AuthMethod)
	}
	if c.SunsetAt == nil {
		t.Error("old contract did not get a sunset_at")
	}
}

func TestContract_Supersede_Validation(t *testing.T) {
	t.Parallel()
	c, _ := contract.New(contract.NewParams{
		ID: contractA, PartnerID: partnerA, AuthMethod: contract.AuthAPIKey,
		Capabilities: []contract.Capability{
			{Name: "x", Tier: contract.TierLow, RateLimitPerMin: 10},
		},
	})
	cases := []struct {
		name string
		p    contract.SupersedeParams
	}{
		{"bad auth", contract.SupersedeParams{
			NewID: "n", AuthMethod: "bogus",
			Capabilities: []contract.Capability{{Name: "x", Tier: contract.TierLow, RateLimitPerMin: 10}},
		}},
		{"empty caps", contract.SupersedeParams{
			NewID: "n", AuthMethod: contract.AuthAPIKey,
		}},
		{"bad rate", contract.SupersedeParams{
			NewID: "n", AuthMethod: contract.AuthAPIKey,
			Capabilities: []contract.Capability{{Name: "x", Tier: contract.TierLow, RateLimitPerMin: -1}},
		}},
		{"bad tier", contract.SupersedeParams{
			NewID: "n", AuthMethod: contract.AuthAPIKey,
			Capabilities: []contract.Capability{{Name: "x", Tier: "bogus", RateLimitPerMin: 10}},
		}},
		{"empty cap name", contract.SupersedeParams{
			NewID: "n", AuthMethod: contract.AuthAPIKey,
			Capabilities: []contract.Capability{{Name: " ", Tier: contract.TierLow, RateLimitPerMin: 10}},
		}},
	}
	for _, c2 := range cases {
		c2 := c2
		t.Run(c2.name, func(t *testing.T) {
			if _, err := c.Supersede(c2.p); err == nil {
				t.Error("expected error")
			}
		})
	}
}

func TestContract_Supersede_RejectsSoftDeleted(t *testing.T) {
	t.Parallel()
	c, _ := contract.New(contract.NewParams{
		ID: contractA, PartnerID: partnerA, AuthMethod: contract.AuthAPIKey,
		Capabilities: []contract.Capability{
			{Name: "x", Tier: contract.TierLow, RateLimitPerMin: 10},
		},
	})
	c.SoftDelete()
	if _, err := c.Supersede(contract.SupersedeParams{
		NewID: "n", AuthMethod: contract.AuthAPIKey,
		Capabilities: []contract.Capability{{Name: "x", Tier: contract.TierLow, RateLimitPerMin: 10}},
	}); err == nil {
		t.Error("expected error superseding soft-deleted contract")
	}
}

func TestContract_New_RejectsEmptyID(t *testing.T) {
	t.Parallel()
	_, err := contract.New(contract.NewParams{
		ID:         "  ",
		PartnerID:  partnerA,
		AuthMethod: contract.AuthAPIKey,
		Capabilities: []contract.Capability{
			{Name: "x", Tier: contract.TierLow, RateLimitPerMin: 10},
		},
	})
	if err == nil {
		t.Error("expected error for empty ID")
	}
}

func TestContract_New_RejectsEmptyCapName(t *testing.T) {
	t.Parallel()
	_, err := contract.New(contract.NewParams{
		ID:         contractA,
		PartnerID:  partnerA,
		AuthMethod: contract.AuthAPIKey,
		Capabilities: []contract.Capability{
			{Name: " ", Tier: contract.TierLow, RateLimitPerMin: 10},
		},
	})
	if err == nil {
		t.Error("expected error for empty cap name")
	}
}
