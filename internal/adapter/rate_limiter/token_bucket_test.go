// Package rate_limiter_test exercises the token-bucket per-AGID rate limiter
// per task spec.
//
// CRITICAL invariants:
//   - Token bucket per AGID (isolation across AGIDs)
//   - Refill at configured rate; max burst capacity respected
//   - Allow() returns false when tokens exhausted
//   - RetryAfter() returns approximate wait seconds when denied
//   - Configure() (re)sets the bucket policy
//
// TDD RED phase — implementation does NOT yet exist.
package rate_limiter_test

import (
	"testing"
	"time"

	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/rate_limiter"
)

const (
	agidA = "agid:01970000-0000-7000-a000-000000000001:recommend:01"
	agidB = "agid:01970000-0000-7000-a000-000000000002:recommend:01"
)

func TestTokenBucket_AllowsUpToBurst(t *testing.T) {
	t.Parallel()
	rl := rate_limiter.NewTokenBucket()
	rl.Configure(agidA, rate_limiter.Policy{
		RatePerMinute: 60,
		Burst:         5,
	})
	for i := 0; i < 5; i++ {
		if !rl.Allow(agidA) {
			t.Fatalf("call %d denied; burst=5", i+1)
		}
	}
	if rl.Allow(agidA) {
		t.Error("6th call should be denied; burst=5 exhausted")
	}
}

func TestTokenBucket_AGIDIsolation(t *testing.T) {
	t.Parallel()
	rl := rate_limiter.NewTokenBucket()
	rl.Configure(agidA, rate_limiter.Policy{RatePerMinute: 60, Burst: 1})
	rl.Configure(agidB, rate_limiter.Policy{RatePerMinute: 60, Burst: 1})

	if !rl.Allow(agidA) {
		t.Fatal("agidA first call denied")
	}
	if !rl.Allow(agidB) {
		t.Fatal("agidB first call denied")
	}
	if rl.Allow(agidA) {
		t.Error("agidA second call should be denied")
	}
	if rl.Allow(agidB) {
		t.Error("agidB second call should be denied")
	}
}

func TestTokenBucket_Refills(t *testing.T) {
	t.Parallel()
	rl := rate_limiter.NewTokenBucket()
	// 1200 per minute = 20 per second = 1 per 50ms.
	rl.Configure(agidA, rate_limiter.Policy{
		RatePerMinute: 1200,
		Burst:         1,
	})
	if !rl.Allow(agidA) {
		t.Fatal("first call denied")
	}
	if rl.Allow(agidA) {
		t.Fatal("second immediate call should be denied")
	}
	time.Sleep(80 * time.Millisecond)
	if !rl.Allow(agidA) {
		t.Error("call after refill window should be allowed")
	}
}

func TestTokenBucket_DeniesUnconfigured(t *testing.T) {
	t.Parallel()
	rl := rate_limiter.NewTokenBucket()
	// Production behaviour: deny by default for unknown AGIDs.
	if rl.Allow("agid:unknown:cap:01") {
		t.Error("unconfigured AGID should be denied")
	}
}

func TestTokenBucket_RetryAfterMatchesPolicy(t *testing.T) {
	t.Parallel()
	rl := rate_limiter.NewTokenBucket()
	rl.Configure(agidA, rate_limiter.Policy{RatePerMinute: 60, Burst: 1})
	_ = rl.Allow(agidA)
	if rl.Allow(agidA) {
		t.Fatal("burst-2 call should be denied")
	}
	wait := rl.RetryAfter(agidA)
	// At 60/min the next token arrives in ~1s; allow some slack.
	if wait <= 0 || wait > 2*time.Second {
		t.Errorf("RetryAfter = %v; want (0, 2s]", wait)
	}
}

func TestTokenBucket_TierDefaults(t *testing.T) {
	t.Parallel()
	// PolicyForTier helper returns a sensible default per tier.
	tests := []struct {
		tier string
	}{
		{"low"}, {"medium"}, {"high"}, {"critical"},
	}
	for _, tt := range tests {
		p := rate_limiter.PolicyForTier(tt.tier)
		if p.RatePerMinute <= 0 {
			t.Errorf("PolicyForTier(%s).RatePerMinute = %d; want > 0", tt.tier, p.RatePerMinute)
		}
		if p.Burst <= 0 {
			t.Errorf("PolicyForTier(%s).Burst = %d; want > 0", tt.tier, p.Burst)
		}
	}
	// Critical tier should be at least as permissive as low.
	low := rate_limiter.PolicyForTier("low")
	crit := rate_limiter.PolicyForTier("critical")
	if crit.RatePerMinute < low.RatePerMinute {
		t.Errorf("critical=%d should be >= low=%d", crit.RatePerMinute, low.RatePerMinute)
	}
	// Unknown tier defaults to the low policy (never zero / never panics).
	unk := rate_limiter.PolicyForTier("platinum")
	if unk.RatePerMinute <= 0 || unk.Burst <= 0 {
		t.Errorf("unknown tier policy = %+v; want low defaults", unk)
	}
}

func TestTokenBucket_ConfigureWithZeroBurst_DefaultsToReactAuth(t *testing.T) {
	t.Parallel()
	rl := rate_limiter.NewTokenBucket()
	// Burst 0 → defaults to RatePerMinute/60 = 120/60 = 2.
	rl.Configure(agidA, rate_limiter.Policy{RatePerMinute: 120, Burst: 0})
	if !rl.Allow(agidA) || !rl.Allow(agidA) {
		t.Fatal("expected the two defaulted burst tokens to be allowed")
	}
	if rl.Allow(agidA) {
		t.Error("3rd call should be denied; default burst = 2")
	}

	// Sub-second rate clamps burst to >= 1 (30/min → 30/60 = 0 → 1).
	rl.Configure(agidB, rate_limiter.Policy{RatePerMinute: 30, Burst: 0})
	if !rl.Allow(agidB) {
		t.Error("expected single defaulted token to be allowed")
	}
	if rl.Allow(agidB) {
		t.Error("2nd call should be denied; default burst clamped to 1")
	}
}
