// Package invocation_test exercises the Invocation aggregate + AuditEntry.
//
// Per ADR-132 + task spec: every /a2a/invoke writes an audit entry; the
// invocation aggregate captures the per-call outcome (capability, status,
// latency, error_code).
//
// CRITICAL invariants:
//   - AGID required, non-empty
//   - PartnerID required, non-empty
//   - Capability required, non-empty
//   - Status: started → completed | failed | rate_limited | scope_denied
//   - Each terminal transition records EndedAt
//   - Latency in milliseconds, computed at terminal transition (>= 0)
//   - Audit entry NEVER carries a GCID (AGID-only, like Session)
//
// TDD RED phase — implementation does NOT yet exist.
package invocation_test

import (
	"strings"
	"testing"
	"time"

	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/invocation"
)

const (
	agidA      = "agid:01970000-0000-7000-a000-000000000001:recommend:01"
	partnerIDA = "01970000-0000-7000-a000-000000000001"
	invocIDA   = "01970000-0000-7000-e000-000000000001"
	correlIDA  = "01970000-0000-7000-c000-000000000001"
)

func TestNewInvocation_StartsInStartedStatus(t *testing.T) {
	t.Parallel()
	i, err := invocation.New(invocation.NewParams{
		ID:            invocIDA,
		AGID:          agidA,
		PartnerID:     partnerIDA,
		Capability:    "recommend_content",
		CorrelationID: correlIDA,
		Endpoint:      "https://a2a.chora.site/a2a/invoke#recommend_content",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if i.Status != invocation.StatusStarted {
		t.Errorf("Status = %q; want started", i.Status)
	}
	if i.AGID != agidA {
		t.Errorf("AGID = %q", i.AGID)
	}
	if i.StartedAt.IsZero() {
		t.Error("StartedAt zero")
	}
	if i.EndedAt != nil {
		t.Error("EndedAt non-nil on creation")
	}
	if i.Endpoint != "https://a2a.chora.site/a2a/invoke#recommend_content" {
		t.Errorf("Endpoint = %q; want canonical capability URL", i.Endpoint)
	}
}

func TestNewInvocation_PersistsEndpoint(t *testing.T) {
	t.Parallel()
	i, err := invocation.New(invocation.NewParams{
		ID:            invocIDA,
		AGID:          agidA,
		PartnerID:     partnerIDA,
		Capability:    "recommend_content",
		CorrelationID: correlIDA,
		Endpoint:      "https://partner.example/a2a/v1/recommend_content",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if i.Endpoint != "https://partner.example/a2a/v1/recommend_content" {
		t.Errorf("Endpoint = %q; want partner-domain URL preserved", i.Endpoint)
	}
}

func TestNewInvocation_AcceptsEmptyEndpoint(t *testing.T) {
	// Endpoint is optional at construction — legacy rows / scope-denied early
	// rejections may not have a resolved endpoint. Empty string is honest;
	// callers MUST NOT substitute a placeholder like "unknown".
	t.Parallel()
	i, err := invocation.New(invocation.NewParams{
		ID:            invocIDA,
		AGID:          agidA,
		PartnerID:     partnerIDA,
		Capability:    "recommend_content",
		CorrelationID: correlIDA,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if i.Endpoint != "" {
		t.Errorf("Endpoint = %q; want empty (null contract — no placeholder)", i.Endpoint)
	}
}

func TestNew_RejectsEmptyAGID(t *testing.T) {
	t.Parallel()
	_, err := invocation.New(invocation.NewParams{
		ID:            invocIDA,
		AGID:          "",
		PartnerID:     partnerIDA,
		Capability:    "x",
		CorrelationID: correlIDA,
	})
	if err == nil {
		t.Error("expected error for empty AGID; got nil")
	}
}

func TestNew_RejectsEmptyPartnerID(t *testing.T) {
	t.Parallel()
	_, err := invocation.New(invocation.NewParams{
		ID:            invocIDA,
		AGID:          agidA,
		PartnerID:     "",
		Capability:    "x",
		CorrelationID: correlIDA,
	})
	if err == nil {
		t.Error("expected error for empty PartnerID; got nil")
	}
}

func TestNew_RejectsEmptyCapability(t *testing.T) {
	t.Parallel()
	_, err := invocation.New(invocation.NewParams{
		ID:            invocIDA,
		AGID:          agidA,
		PartnerID:     partnerIDA,
		Capability:    "",
		CorrelationID: correlIDA,
	})
	if err == nil {
		t.Error("expected error for empty Capability; got nil")
	}
}

func TestComplete_TransitionsAndComputesLatency(t *testing.T) {
	t.Parallel()
	i, _ := invocation.New(invocation.NewParams{
		ID:            invocIDA,
		AGID:          agidA,
		PartnerID:     partnerIDA,
		Capability:    "recommend_content",
		CorrelationID: correlIDA,
	})
	time.Sleep(2 * time.Millisecond) // ensure latency > 0
	if err := i.Complete(64); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if i.Status != invocation.StatusCompleted {
		t.Errorf("Status = %q; want completed", i.Status)
	}
	if i.EndedAt == nil {
		t.Error("EndedAt nil after Complete")
	}
	if i.LatencyMS < 0 {
		t.Errorf("LatencyMS = %d; want >= 0", i.LatencyMS)
	}
	if i.ResponseSizeBytes != 64 {
		t.Errorf("ResponseSizeBytes = %d; want 64", i.ResponseSizeBytes)
	}
}

func TestFail_TransitionsAndStoresErrorCode(t *testing.T) {
	t.Parallel()
	i, _ := invocation.New(invocation.NewParams{
		ID:            invocIDA,
		AGID:          agidA,
		PartnerID:     partnerIDA,
		Capability:    "recommend_content",
		CorrelationID: correlIDA,
	})
	if err := i.Fail("UPSTREAM_TIMEOUT"); err != nil {
		t.Fatalf("Fail: %v", err)
	}
	if i.Status != invocation.StatusFailed {
		t.Errorf("Status = %q", i.Status)
	}
	if i.ErrorCode != "UPSTREAM_TIMEOUT" {
		t.Errorf("ErrorCode = %q", i.ErrorCode)
	}
}

func TestRateLimited_TerminalTransition(t *testing.T) {
	t.Parallel()
	i, _ := invocation.New(invocation.NewParams{
		ID:            invocIDA,
		AGID:          agidA,
		PartnerID:     partnerIDA,
		Capability:    "recommend_content",
		CorrelationID: correlIDA,
	})
	if err := i.RateLimit(); err != nil {
		t.Fatalf("RateLimit: %v", err)
	}
	if i.Status != invocation.StatusRateLimited {
		t.Errorf("Status = %q", i.Status)
	}
	if i.EndedAt == nil {
		t.Error("EndedAt nil")
	}
}

func TestScopeDenied_TerminalTransition(t *testing.T) {
	t.Parallel()
	i, _ := invocation.New(invocation.NewParams{
		ID:            invocIDA,
		AGID:          agidA,
		PartnerID:     partnerIDA,
		Capability:    "recommend_content",
		CorrelationID: correlIDA,
	})
	if err := i.ScopeDeny("not_in_contract"); err != nil {
		t.Fatalf("ScopeDeny: %v", err)
	}
	if i.Status != invocation.StatusScopeDenied {
		t.Errorf("Status = %q", i.Status)
	}
}

func TestComplete_RejectedAfterTerminal(t *testing.T) {
	t.Parallel()
	i, _ := invocation.New(invocation.NewParams{
		ID:            invocIDA,
		AGID:          agidA,
		PartnerID:     partnerIDA,
		Capability:    "recommend_content",
		CorrelationID: correlIDA,
	})
	_ = i.Complete(10)
	if err := i.Complete(20); err == nil {
		t.Error("expected error completing twice; got nil")
	}
}

// MarshalAuditEntry returns a textual representation; it MUST NOT contain
// a "gcid" key (AGID-only audit per CLAUDE.md §1).
func TestMarshalAuditEntry_NoGCID(t *testing.T) {
	t.Parallel()
	i, _ := invocation.New(invocation.NewParams{
		ID:            invocIDA,
		AGID:          agidA,
		PartnerID:     partnerIDA,
		Capability:    "recommend_content",
		CorrelationID: correlIDA,
	})
	_ = i.Complete(10)
	out := invocation.MarshalAuditEntry(i)
	if out == "" {
		t.Fatal("MarshalAuditEntry empty")
	}
	if containsCaseInsensitive(out, "gcid") {
		t.Errorf("MarshalAuditEntry contains forbidden 'gcid' key: %s", out)
	}
}

// Audit entry MUST include the dispatch endpoint when present (per the O+
// A2A console audit-trail requirement — debt-clearing of the M12 TODO).
func TestMarshalAuditEntry_IncludesEndpoint(t *testing.T) {
	t.Parallel()
	i, _ := invocation.New(invocation.NewParams{
		ID:            invocIDA,
		AGID:          agidA,
		PartnerID:     partnerIDA,
		Capability:    "recommend_content",
		CorrelationID: correlIDA,
		Endpoint:      "https://a2a.chora.site/a2a/invoke#recommend_content",
	})
	_ = i.Complete(10)
	out := invocation.MarshalAuditEntry(i)
	if !strings.Contains(out, `"endpoint":"https://a2a.chora.site/a2a/invoke#recommend_content"`) {
		t.Errorf("MarshalAuditEntry missing endpoint field: %s", out)
	}
}

// containsCaseInsensitive is a small helper to keep the test self-contained.
func containsCaseInsensitive(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		match := true
		for j := 0; j < len(sub); j++ {
			c := s[i+j]
			d := sub[j]
			if c >= 'A' && c <= 'Z' {
				c += 32
			}
			if d >= 'A' && d <= 'Z' {
				d += 32
			}
			if c != d {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
