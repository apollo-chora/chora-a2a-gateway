// Package dns provides the DNS-TXT partner-verification adapter.
//
// Per ADR-132 §8 partner onboarding includes a DNS-TXT verification step:
// the partner declares
//
//	_chora-a2a.{partner_domain}  IN TXT  "chora-a2a-verify={token}"
//
// chora-a2a-gateway resolves the record, validates the token matches the
// one minted at registration, and on success enables AGID issuance.
//
// The Resolver port is decoupled from the verifier so tests can inject a
// MockResolver. Production wires the GoLookupResolver which delegates to
// net.LookupTXT (with a small in-memory TTL cache).
package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// Resolver is the port for resolving TXT records. The default cache TTL is
// 5 minutes; callers can override per-instance.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// MockResolver is the test adapter — pre-seeded TXT responses keyed by name.
type MockResolver struct {
	mu      sync.RWMutex
	records map[string][]string
	errs    map[string]error
}

// NewMockResolver constructs an empty mock.
func NewMockResolver() *MockResolver {
	return &MockResolver{
		records: make(map[string][]string),
		errs:    make(map[string]error),
	}
}

// SeedTXT adds a TXT response for a name.
func (m *MockResolver) SeedTXT(name string, txt []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records[name] = txt
}

// SeedError adds an error response for a name.
func (m *MockResolver) SeedError(name string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errs[name] = err
}

// LookupTXT returns the seeded TXT response or an error.
func (m *MockResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if e, ok := m.errs[name]; ok {
		return nil, e
	}
	if r, ok := m.records[name]; ok {
		return r, nil
	}
	return nil, fmt.Errorf("dns: no TXT record for %s", name)
}

// GoLookupResolver delegates to the net package and caches results for TTL.
//
// Skeleton uses net.LookupTXT directly (TTL is best-effort via the resolver
// itself). M12 may swap in a Cloud DNS-aware resolver to honour real TTLs.
type GoLookupResolver struct {
	mu    sync.Mutex
	cache map[string]cachedTXT

	// TTL is the cache TTL for positive responses (default 5 minutes).
	TTL time.Duration
}

type cachedTXT struct {
	txt []string
	at  time.Time
}

// NewGoLookupResolver constructs a production-style DNS resolver.
func NewGoLookupResolver() *GoLookupResolver {
	return &GoLookupResolver{
		cache: make(map[string]cachedTXT),
		TTL:   5 * time.Minute,
	}
}

// LookupTXT delegates to net.LookupTXT with a small in-memory cache.
func (r *GoLookupResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	r.mu.Lock()
	if c, ok := r.cache[name]; ok && time.Since(c.at) < r.TTL {
		out := append([]string(nil), c.txt...)
		r.mu.Unlock()
		return out, nil
	}
	r.mu.Unlock()
	res := net.DefaultResolver
	txt, err := res.LookupTXT(ctx, name)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.cache[name] = cachedTXT{txt: append([]string(nil), txt...), at: time.Now()}
	r.mu.Unlock()
	return txt, nil
}

// VerifyResult is the outcome of a verification attempt.
type VerifyResult struct {
	Verified bool
	At       time.Time
	Reason   string
}

// Verifier wraps a Resolver with the chora-a2a-verify token comparator.
type Verifier struct {
	r Resolver
}

// NewVerifier constructs a verifier.
func NewVerifier(r Resolver) *Verifier {
	if r == nil {
		r = NewGoLookupResolver()
	}
	return &Verifier{r: r}
}

// Verify checks _chora-a2a.{domain} TXT for `chora-a2a-verify={token}`.
//
// On match the returned VerifyResult.Verified == true and At is the verify
// timestamp. On mismatch (record absent / token stale) Reason describes the
// failure reason for audit.
func (v *Verifier) Verify(ctx context.Context, domain, token string) VerifyResult {
	domain = strings.TrimSpace(strings.TrimSuffix(strings.ToLower(domain), "."))
	if domain == "" {
		return VerifyResult{Reason: "DOMAIN_EMPTY"}
	}
	if token == "" {
		return VerifyResult{Reason: "TOKEN_EMPTY"}
	}
	host := "_chora-a2a." + domain
	records, err := v.r.LookupTXT(ctx, host)
	if err != nil {
		return VerifyResult{Reason: "DNS_LOOKUP_ERROR: " + err.Error()}
	}
	want := "chora-a2a-verify=" + token
	for _, txt := range records {
		txt = strings.TrimSpace(txt)
		if txt == want {
			return VerifyResult{Verified: true, At: time.Now().UTC()}
		}
	}
	return VerifyResult{Reason: "TXT_RECORD_MISMATCH"}
}

// ErrDomainEmpty is returned when an empty domain is supplied.
var ErrDomainEmpty = errors.New("dns: domain empty")
