// Package inmem provides in-memory adapters for the chora-a2a-gateway
// skeleton. Real impl in M12 will swap these for Postgres repos
// (chora_a2a database) + a Valkey-backed store for the rate limiter.
//
// Adapters:
//   - PartnerStore     — A2APartnerRegistry persistence
//   - SessionStore     — append-only session log
//   - IdentityStore    — ExternalAgentIdentity persistence
//   - RateLimiter      — per-AGID token-bucket rate limiter
package inmem

import (
	"errors"
	"sync"
	"time"

	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/agent_identity"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/partner"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/session"
)

// ErrNotFound is returned when a requested entity does not exist.
var ErrNotFound = errors.New("inmem: not found")

// ErrAlreadyExists is returned when attempting to add a duplicate entity.
var ErrAlreadyExists = errors.New("inmem: already exists")

// -----------------------------------------------------------------------------
// PartnerStore
// -----------------------------------------------------------------------------

type PartnerStore struct {
	mu sync.RWMutex
	m  map[string]*partner.Partner
}

func NewPartnerStore() *PartnerStore {
	return &PartnerStore{m: make(map[string]*partner.Partner)}
}

// Put inserts or updates a partner.
func (s *PartnerStore) Put(p *partner.Partner) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[p.AGID] = p
	return nil
}

// Get fetches a partner by AGID.
func (s *PartnerStore) Get(agid string) (*partner.Partner, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.m[agid]
	if !ok {
		return nil, ErrNotFound
	}
	return p, nil
}

// -----------------------------------------------------------------------------
// SessionStore — append-only
// -----------------------------------------------------------------------------

type SessionStore struct {
	mu sync.RWMutex
	m  map[string]*session.Session // keyed by correlation_id
}

func NewSessionStore() *SessionStore {
	return &SessionStore{m: make(map[string]*session.Session)}
}

// Append inserts a new session. Rejects duplicates by correlation_id —
// append-only invariant.
func (s *SessionStore) Append(sess *session.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[sess.CorrelationID]; ok {
		return ErrAlreadyExists
	}
	s.m[sess.CorrelationID] = sess
	return nil
}

// GetByCorrelationID fetches a session.
func (s *SessionStore) GetByCorrelationID(corr string) (*session.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.m[corr]
	if !ok {
		return nil, ErrNotFound
	}
	return sess, nil
}

// -----------------------------------------------------------------------------
// IdentityStore
// -----------------------------------------------------------------------------

type IdentityStore struct {
	mu sync.RWMutex
	m  map[string]*agent_identity.ExternalAgentIdentity
}

func NewIdentityStore() *IdentityStore {
	return &IdentityStore{m: make(map[string]*agent_identity.ExternalAgentIdentity)}
}

func (s *IdentityStore) Put(id *agent_identity.ExternalAgentIdentity) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[id.AGID] = id
	return nil
}

func (s *IdentityStore) Get(agid string) (*agent_identity.ExternalAgentIdentity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.m[agid]
	if !ok {
		return nil, ErrNotFound
	}
	return id, nil
}

// -----------------------------------------------------------------------------
// RateLimiter — per-AGID token bucket
// -----------------------------------------------------------------------------

// bucket tracks consumed tokens within a window.
type bucket struct {
	limit       int
	window      time.Duration
	count       int
	windowStart time.Time
}

// RateLimiter is a per-AGID token-bucket rate limiter.
//
// Skeleton notes:
//   - Tokens reset at the start of each window (simple sliding-window
//     reset semantics rather than full sliding window — fine for the
//     skeleton).
//   - Unconfigured AGIDs are permissive (returns true). Real impl in M12
//     will deny by default.
type RateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

func NewRateLimiter() *RateLimiter {
	return &RateLimiter{buckets: make(map[string]*bucket)}
}

// Configure sets or replaces the rate-limit policy for the given AGID.
func (r *RateLimiter) Configure(agid string, limit int, window time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buckets[agid] = &bucket{
		limit:       limit,
		window:      window,
		windowStart: time.Now(),
	}
}

// Allow consumes one token from the AGID's bucket. Returns false if the
// bucket has no tokens left within the current window.
func (r *RateLimiter) Allow(agid string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	b, ok := r.buckets[agid]
	if !ok {
		// Unconfigured AGID — permissive (skeleton behaviour). Real
		// impl in M12 will deny by default.
		return true
	}

	now := time.Now()
	if now.Sub(b.windowStart) >= b.window {
		b.count = 0
		b.windowStart = now
	}
	if b.count >= b.limit {
		return false
	}
	b.count++
	return true
}
