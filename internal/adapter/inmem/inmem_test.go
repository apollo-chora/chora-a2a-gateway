// Package inmem_test exercises the in-memory adapters: PartnerStore,
// SessionStore (append-only), IdentityStore, and the per-AGID token-bucket
// RateLimiter.
//
// Real impl in M12 will replace these with Postgres repos + Valkey
// (Valkey) for the rate limiter (per CLAUDE.md §1 cache).
//
// TDD RED phase — implementation does NOT yet exist.
package inmem_test

import (
	"testing"
	"time"

	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/inmem"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/agent_identity"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/partner"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/session"
)

const (
	agidA = "01970000-0000-7000-b000-000000000001"
	agidB = "01970000-0000-7000-b000-000000000002"
	corrA = "01970000-0000-7000-c000-000000000001"
	pubA  = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n-----END PUBLIC KEY-----"
)

// -----------------------------------------------------------------------------
// PartnerStore
// -----------------------------------------------------------------------------

func TestPartnerStore_PutAndGet(t *testing.T) {
	t.Parallel()
	store := inmem.NewPartnerStore()
	p, _ := partner.New(partner.NewParams{
		AGID:            agidA,
		Name:            "Acme",
		AllowedScopes:   []string{"recommend_content"},
		RateLimitPerMin: 100,
		QuotaPerDay:     10000,
	})
	if err := store.Put(p); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := store.Get(agidA)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.AGID != agidA {
		t.Errorf("AGID = %q; want %q", got.AGID, agidA)
	}
}

func TestPartnerStore_GetNotFound(t *testing.T) {
	t.Parallel()
	store := inmem.NewPartnerStore()
	_, err := store.Get("01970000-0000-7000-b000-00000000ffff")
	if err == nil {
		t.Error("expected ErrNotFound; got nil")
	}
}

// -----------------------------------------------------------------------------
// SessionStore — append-only
// -----------------------------------------------------------------------------

func TestSessionStore_AppendAndGet(t *testing.T) {
	t.Parallel()
	store := inmem.NewSessionStore()
	s, _ := session.New(session.NewParams{
		CorrelationID: corrA,
		AGID:          agidA,
		Action:        "x",
	})
	if err := store.Append(s); err != nil {
		t.Fatalf("Append: %v", err)
	}
	got, err := store.GetByCorrelationID(corrA)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.AGID != agidA {
		t.Errorf("AGID = %q; want %q", got.AGID, agidA)
	}
}

// Append-only: cannot append two sessions with the same correlation_id.
func TestSessionStore_AppendDuplicateRejected(t *testing.T) {
	t.Parallel()
	store := inmem.NewSessionStore()
	s, _ := session.New(session.NewParams{
		CorrelationID: corrA,
		AGID:          agidA,
		Action:        "x",
	})
	_ = store.Append(s)

	s2, _ := session.New(session.NewParams{
		CorrelationID: corrA,
		AGID:          agidA,
		Action:        "y",
	})
	if err := store.Append(s2); err == nil {
		t.Error("expected duplicate-correlation_id error; got nil")
	}
}

// Append-only: SessionStore exposes no Delete API.
// (compile-time guarantee — if a Delete method is added the build still
// passes, so this test merely documents the invariant via the public API.)

// -----------------------------------------------------------------------------
// IdentityStore
// -----------------------------------------------------------------------------

func TestIdentityStore_PutAndGet(t *testing.T) {
	t.Parallel()
	store := inmem.NewIdentityStore()
	id, _ := agent_identity.New(agent_identity.NewParams{
		AGID:         agidA,
		PublicKeyPEM: pubA,
		Algorithm:    agent_identity.AlgEd25519,
	})
	if err := store.Put(id); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := store.Get(agidA)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.AGID != agidA {
		t.Errorf("AGID = %q; want %q", got.AGID, agidA)
	}
}

// -----------------------------------------------------------------------------
// RateLimiter — per-AGID token bucket
// -----------------------------------------------------------------------------

// 100 calls within a minute succeed; 101st returns false.
func TestRateLimiter_AllowsUpToLimit(t *testing.T) {
	t.Parallel()
	rl := inmem.NewRateLimiter()
	rl.Configure(agidA, 100, time.Minute)

	for i := 0; i < 100; i++ {
		if !rl.Allow(agidA) {
			t.Fatalf("call %d unexpectedly denied", i+1)
		}
	}
	if rl.Allow(agidA) {
		t.Error("101st call should have been denied (limit=100/min)")
	}
}

// Different AGIDs have independent buckets.
func TestRateLimiter_BucketIsolation(t *testing.T) {
	t.Parallel()
	rl := inmem.NewRateLimiter()
	rl.Configure(agidA, 1, time.Minute)
	rl.Configure(agidB, 1, time.Minute)

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

// Bucket refills after the configured window elapses.
func TestRateLimiter_BucketRefills(t *testing.T) {
	t.Parallel()
	rl := inmem.NewRateLimiter()
	// Use a tight window for fast tests.
	rl.Configure(agidA, 2, 50*time.Millisecond)

	if !rl.Allow(agidA) {
		t.Fatal("first call denied")
	}
	if !rl.Allow(agidA) {
		t.Fatal("second call denied")
	}
	if rl.Allow(agidA) {
		t.Fatal("third call should be denied within window")
	}
	time.Sleep(60 * time.Millisecond)
	if !rl.Allow(agidA) {
		t.Error("call after window should be allowed")
	}
}

// Default behaviour: an unconfigured AGID uses an extremely permissive default
// (skeleton only — production will deny by default).
func TestRateLimiter_UnconfiguredAGIDAllows(t *testing.T) {
	t.Parallel()
	rl := inmem.NewRateLimiter()
	if !rl.Allow("01970000-0000-7000-b000-00000000aaaa") {
		t.Error("unconfigured AGID should allow in skeleton")
	}
}
