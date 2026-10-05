// Package rate_limiter provides a per-AGID token-bucket rate limiter.
//
// Skeleton-level adapter; M12 swaps this for a a Valkey-backed store backed
// limiter so per-AGID buckets persist across service replicas.
//
// CRITICAL invariants:
//   - Per-AGID isolation (no cross-AGID interference)
//   - Configure() (re)sets the policy; subsequent Allow() calls use the new
//     policy without leaking burst from the previous policy
//   - Refill is continuous (token-bucket model — fractional tokens accrue
//     at rate / 60 per second)
//   - DENY by default for unconfigured AGIDs (production behaviour, not the
//     skeleton's permissive default)
//   - RetryAfter() returns approximate wait until the next token would be
//     available; 0 when at least one token is currently available
package rate_limiter

import (
	"sync"
	"time"
)

// Policy is the per-AGID rate-limit configuration.
type Policy struct {
	// RatePerMinute is the steady-state refill rate. Must be > 0.
	RatePerMinute int

	// Burst is the bucket capacity (max tokens that can accumulate).
	// Must be > 0. Defaults to RatePerMinute / 60 if zero (i.e. 1s burst).
	Burst int
}

// PolicyForTier returns sensible defaults per partner tier.
func PolicyForTier(tier string) Policy {
	switch tier {
	case "low":
		return Policy{RatePerMinute: 60, Burst: 10}
	case "medium":
		return Policy{RatePerMinute: 300, Burst: 30}
	case "high":
		return Policy{RatePerMinute: 1200, Burst: 60}
	case "critical":
		return Policy{RatePerMinute: 6000, Burst: 120}
	default:
		// Unknown tier → low.
		return Policy{RatePerMinute: 60, Burst: 10}
	}
}

// bucket holds the per-AGID accounting state.
type bucket struct {
	policy       Policy
	tokens       float64
	lastRefillAt time.Time
}

// TokenBucket is the per-AGID token-bucket rate limiter.
type TokenBucket struct {
	mu      sync.Mutex
	buckets map[string]*bucket

	// Now is injectable for tests; defaults to time.Now.
	Now func() time.Time
}

// NewTokenBucket constructs a TokenBucket with deny-by-default semantics
// for unconfigured AGIDs.
func NewTokenBucket() *TokenBucket {
	return &TokenBucket{
		buckets: make(map[string]*bucket),
		Now:     time.Now,
	}
}

// Configure sets or replaces the policy for an AGID. The bucket is reset to
// full (Burst tokens) so a new contract takes effect immediately.
func (r *TokenBucket) Configure(agid string, p Policy) {
	if p.Burst <= 0 {
		// Default: 1s burst at the policy rate.
		p.Burst = p.RatePerMinute / 60
		if p.Burst < 1 {
			p.Burst = 1
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buckets[agid] = &bucket{
		policy:       p,
		tokens:       float64(p.Burst),
		lastRefillAt: r.now(),
	}
}

// Allow consumes one token. Returns true on success, false if the bucket
// is empty (rate-limited). Unconfigured AGIDs always return false.
func (r *TokenBucket) Allow(agid string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	b, ok := r.buckets[agid]
	if !ok {
		return false
	}
	r.refillLocked(b)
	if b.tokens < 1.0 {
		return false
	}
	b.tokens -= 1.0
	return true
}

// RetryAfter returns the approximate wait until the next token will be
// available. Returns 0 when at least one token is currently available, or
// when the AGID is unconfigured (no future refills).
func (r *TokenBucket) RetryAfter(agid string) time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	b, ok := r.buckets[agid]
	if !ok {
		return 0
	}
	r.refillLocked(b)
	if b.tokens >= 1.0 {
		return 0
	}
	missing := 1.0 - b.tokens
	tokensPerSec := float64(b.policy.RatePerMinute) / 60.0
	if tokensPerSec <= 0 {
		return time.Hour
	}
	secs := missing / tokensPerSec
	return time.Duration(secs * float64(time.Second))
}

func (r *TokenBucket) refillLocked(b *bucket) {
	now := r.now()
	delta := now.Sub(b.lastRefillAt)
	if delta <= 0 {
		return
	}
	add := (float64(b.policy.RatePerMinute) / 60.0) * delta.Seconds()
	if add > 0 {
		b.tokens += add
		if max := float64(b.policy.Burst); b.tokens > max {
			b.tokens = max
		}
	}
	b.lastRefillAt = now
}

func (r *TokenBucket) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}
