// Package contract implements the A2AContract aggregate root per ADR-132 §3.
//
// A Contract declares the capabilities a partner may invoke + per-capability
// rate limits + auth method. The aggregate root is identified by `ID`
// (UUIDv7) and references the owning `PartnerID` as a UUID without FK
// constraint (ddd-enforcement #3 — cross-aggregate references are UUIDs only).
//
// CRITICAL invariants:
//   - PartnerID required, non-empty
//   - At least one capability required
//   - Each capability has a positive rate limit per minute and a recognised tier
//   - AuthMethod is one of api_key | jws_ed25519 | oauth2
//   - Soft-delete via DeletedAt (ddd-enforcement #5)
//   - Versioned (semver-style; old versions deprecated with sunset_at)
//
// CRITICAL: NO Gcid field. Contracts bind partners (AGID-keyed), never
// human GCIDs (CLAUDE.md §1 + ddd-enforcement #10).
package contract

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// AuthMethod is the per-contract partner authentication method.
type AuthMethod string

const (
	AuthAPIKey     AuthMethod = "api_key"
	AuthJWSEd25519 AuthMethod = "jws_ed25519"
	AuthOAuth2     AuthMethod = "oauth2"
)

func validAuthMethod(m AuthMethod) bool {
	switch m {
	case AuthAPIKey, AuthJWSEd25519, AuthOAuth2:
		return true
	}
	return false
}

// Tier classifies the per-capability trust tier driving default rate ceilings.
type Tier string

const (
	TierLow      Tier = "low"
	TierMedium   Tier = "medium"
	TierHigh     Tier = "high"
	TierCritical Tier = "critical"
)

func validTier(t Tier) bool {
	switch t {
	case TierLow, TierMedium, TierHigh, TierCritical:
		return true
	}
	return false
}

// TierMaxRateLimit returns the platform-default max rate limit (requests per
// minute) for the given tier. Per-capability values in a contract may be
// lower; values exceeding the tier max should be capped by callers.
func TierMaxRateLimit(t Tier) int {
	switch t {
	case TierLow:
		return 60
	case TierMedium:
		return 300
	case TierHigh:
		return 1200
	case TierCritical:
		return 6000
	}
	return 0
}

// Capability describes one allowed action on a contract.
type Capability struct {
	Name            string
	Tier            Tier
	RateLimitPerMin int
}

// Contract is the aggregate root.
//
// NO Gcid field — contracts bind AGIDs only.
type Contract struct {
	ID           string // UUIDv7
	PartnerID    string // UUIDv7 of owning Registration/Partner aggregate
	AuthMethod   AuthMethod
	Capabilities []Capability

	// Versioning — append-only; old versions superseded but not mutated.
	Version      int        // monotonic; 1 on initial create
	SupersedesID string     // ID of previous version, if any
	SunsetAt     *time.Time // when this version stops accepting calls

	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time
}

// NewParams is the input shape for New.
type NewParams struct {
	ID           string
	PartnerID    string
	AuthMethod   AuthMethod
	Capabilities []Capability
}

// New constructs a Contract enforcing aggregate invariants.
func New(p NewParams) (*Contract, error) {
	if strings.TrimSpace(p.ID) == "" {
		return nil, errors.New("contract: ID required")
	}
	if strings.TrimSpace(p.PartnerID) == "" {
		return nil, errors.New("contract: PartnerID required")
	}
	if !validAuthMethod(p.AuthMethod) {
		return nil, fmt.Errorf("contract: invalid AuthMethod %q", p.AuthMethod)
	}
	if len(p.Capabilities) == 0 {
		return nil, errors.New("contract: at least one Capability required")
	}
	for i, c := range p.Capabilities {
		if strings.TrimSpace(c.Name) == "" {
			return nil, fmt.Errorf("contract: Capabilities[%d].Name required", i)
		}
		if !validTier(c.Tier) {
			return nil, fmt.Errorf("contract: Capabilities[%d].Tier %q invalid", i, c.Tier)
		}
		if c.RateLimitPerMin <= 0 {
			return nil, fmt.Errorf("contract: Capabilities[%d].RateLimitPerMin must be > 0; got %d",
				i, c.RateLimitPerMin)
		}
	}

	caps := make([]Capability, len(p.Capabilities))
	copy(caps, p.Capabilities)

	now := time.Now().UTC()
	return &Contract{
		ID:           strings.TrimSpace(p.ID),
		PartnerID:    strings.TrimSpace(p.PartnerID),
		AuthMethod:   p.AuthMethod,
		Capabilities: caps,
		Version:      1,
		CreatedAt:    now,
		UpdatedAt:    now,
	}, nil
}

// HasCapability reports whether the named capability is in the contract's
// allow-list and the contract is active.
func (c *Contract) HasCapability(name string) bool {
	if c.DeletedAt != nil {
		return false
	}
	for _, x := range c.Capabilities {
		if x.Name == name {
			return true
		}
	}
	return false
}

// RateLimitFor returns the rate-limit-per-minute for the named capability.
// Returns 0 if the capability is not in the contract.
func (c *Contract) RateLimitFor(name string) int {
	for _, x := range c.Capabilities {
		if x.Name == name {
			return x.RateLimitPerMin
		}
	}
	return 0
}

// TierFor returns the tier of the named capability. Returns "" if absent.
func (c *Contract) TierFor(name string) Tier {
	for _, x := range c.Capabilities {
		if x.Name == name {
			return x.Tier
		}
	}
	return ""
}

// SoftDelete marks the contract as deleted (ddd-enforcement #5).
func (c *Contract) SoftDelete() {
	now := time.Now().UTC()
	c.DeletedAt = &now
	c.UpdatedAt = now
}

// IsActive reports whether the contract is in a state that permits invocations.
func (c *Contract) IsActive() bool {
	if c.DeletedAt != nil {
		return false
	}
	if c.SunsetAt != nil && time.Now().UTC().After(*c.SunsetAt) {
		return false
	}
	return true
}

// SupersedeParams captures a new version's payload.
type SupersedeParams struct {
	NewID        string
	Capabilities []Capability
	AuthMethod   AuthMethod
	SunsetAfter  time.Duration // how long the OLD version remains accepting calls
}

// Supersede creates a new contract version that replaces this one. The
// previous (current) contract is marked with a sunset_at horizon; the new
// contract has Version+1 and SupersedesID = old.ID. Supersede is the ONLY
// way to mutate a contract — version rows are immutable beyond their
// sunset stamp.
func (c *Contract) Supersede(p SupersedeParams) (*Contract, error) {
	if c.DeletedAt != nil {
		return nil, errors.New("contract: cannot supersede a soft-deleted contract")
	}
	if !validAuthMethod(p.AuthMethod) {
		return nil, fmt.Errorf("contract: invalid AuthMethod %q", p.AuthMethod)
	}
	if len(p.Capabilities) == 0 {
		return nil, errors.New("contract: at least one Capability required")
	}
	for i, x := range p.Capabilities {
		if strings.TrimSpace(x.Name) == "" {
			return nil, fmt.Errorf("contract: Capabilities[%d].Name required", i)
		}
		if !validTier(x.Tier) {
			return nil, fmt.Errorf("contract: Capabilities[%d].Tier %q invalid", i, x.Tier)
		}
		if x.RateLimitPerMin <= 0 {
			return nil, fmt.Errorf("contract: Capabilities[%d].RateLimitPerMin must be > 0", i)
		}
	}
	caps := make([]Capability, len(p.Capabilities))
	copy(caps, p.Capabilities)

	now := time.Now().UTC()
	sunset := now.Add(p.SunsetAfter)
	c.SunsetAt = &sunset
	c.UpdatedAt = now

	return &Contract{
		ID:           strings.TrimSpace(p.NewID),
		PartnerID:    c.PartnerID,
		AuthMethod:   p.AuthMethod,
		Capabilities: caps,
		Version:      c.Version + 1,
		SupersedesID: c.ID,
		CreatedAt:    now,
		UpdatedAt:    now,
	}, nil
}
