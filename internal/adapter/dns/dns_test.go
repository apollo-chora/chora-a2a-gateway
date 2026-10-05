// Package dns_test exercises the DNS-TXT verifier per ADR-132 §8.
//
// CRITICAL invariants:
//   - Verifier checks _chora-a2a.{domain} TXT for chora-a2a-verify={token}
//   - Mismatch returns Verified=false with a Reason for audit
//   - DNS lookup error returns Verified=false (no panic)
//   - Domain canonicalised (lowercase + trim trailing dot)
//   - Mock resolver supports seeded responses + errors
package dns_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/dns"
)

func TestVerifier_Match(t *testing.T) {
	t.Parallel()
	mr := dns.NewMockResolver()
	mr.SeedTXT("_chora-a2a.acme.example", []string{
		"some-other-record",
		"chora-a2a-verify=tok-123",
	})
	v := dns.NewVerifier(mr)
	res := v.Verify(context.Background(), "acme.example", "tok-123")
	if !res.Verified {
		t.Fatalf("expected verified; got reason=%s", res.Reason)
	}
	if res.At.IsZero() {
		t.Error("expected At to be set on success")
	}
}

func TestVerifier_DomainNormalisation(t *testing.T) {
	t.Parallel()
	mr := dns.NewMockResolver()
	mr.SeedTXT("_chora-a2a.acme.example", []string{"chora-a2a-verify=t"})
	v := dns.NewVerifier(mr)
	// upper case + trailing dot
	res := v.Verify(context.Background(), "ACME.example.", "t")
	if !res.Verified {
		t.Errorf("normalisation failed: %s", res.Reason)
	}
}

func TestVerifier_NoMatch(t *testing.T) {
	t.Parallel()
	mr := dns.NewMockResolver()
	mr.SeedTXT("_chora-a2a.acme.example", []string{"chora-a2a-verify=other"})
	v := dns.NewVerifier(mr)
	res := v.Verify(context.Background(), "acme.example", "tok-mine")
	if res.Verified {
		t.Error("expected mismatch")
	}
	if !strings.Contains(res.Reason, "MISMATCH") {
		t.Errorf("Reason = %q", res.Reason)
	}
}

func TestVerifier_LookupError(t *testing.T) {
	t.Parallel()
	mr := dns.NewMockResolver()
	mr.SeedError("_chora-a2a.broken.example", errors.New("NXDOMAIN"))
	v := dns.NewVerifier(mr)
	res := v.Verify(context.Background(), "broken.example", "tok")
	if res.Verified {
		t.Error("expected unverified on lookup error")
	}
	if !strings.Contains(res.Reason, "DNS_LOOKUP_ERROR") {
		t.Errorf("Reason = %q", res.Reason)
	}
}

func TestVerifier_EmptyInputs(t *testing.T) {
	t.Parallel()
	v := dns.NewVerifier(dns.NewMockResolver())
	if r := v.Verify(context.Background(), "", "tok"); r.Verified || r.Reason != "DOMAIN_EMPTY" {
		t.Errorf("empty domain reason = %q", r.Reason)
	}
	if r := v.Verify(context.Background(), "acme.example", ""); r.Verified || r.Reason != "TOKEN_EMPTY" {
		t.Errorf("empty token reason = %q", r.Reason)
	}
}

func TestMockResolver_LookupTXT_NotFound(t *testing.T) {
	t.Parallel()
	mr := dns.NewMockResolver()
	if _, err := mr.LookupTXT(context.Background(), "absent.example"); err == nil {
		t.Error("expected error for absent")
	}
}

func TestGoLookupResolver_Construct(t *testing.T) {
	t.Parallel()
	r := dns.NewGoLookupResolver()
	if r == nil {
		t.Fatal("nil")
	}
	if r.TTL <= 0 {
		t.Errorf("TTL = %v", r.TTL)
	}
}

// NewVerifier(nil) falls back to the production GoLookupResolver. Verify an
// empty domain right away so the default resolver is constructed WITHOUT any
// real DNS dependency (the empty domain short-circuits before LookupTXT).
func TestNewVerifier_NilResolverConstructsDefault(t *testing.T) {
	t.Parallel()
	v := dns.NewVerifier(nil)
	res := v.Verify(context.Background(), "", "tok")
	if res.Verified {
		t.Error("empty domain must not verify")
	}
	if res.Reason != "DOMAIN_EMPTY" {
		t.Errorf("Reason = %q; want DOMAIN_EMPTY", res.Reason)
	}
}
