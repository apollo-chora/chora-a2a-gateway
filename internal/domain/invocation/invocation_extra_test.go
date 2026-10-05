// Package invocation_test — extra coverage for IsTerminal, MarshalAuditEntry,
// and the empty-EndedAt path in MarshalAuditEntry.
package invocation_test

import (
	"strings"
	"testing"

	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/invocation"
)

func TestInvocation_IsTerminal(t *testing.T) {
	t.Parallel()
	i, _ := invocation.New(invocation.NewParams{
		ID: invocIDA, AGID: agidA, PartnerID: partnerIDA, Capability: "x", CorrelationID: correlIDA,
	})
	if i.IsTerminal() {
		t.Error("fresh invocation reports IsTerminal=true")
	}
	_ = i.Complete(0)
	if !i.IsTerminal() {
		t.Error("after Complete, IsTerminal=false")
	}
}

func TestInvocation_MarshalAuditEntry_StartedHasEmptyEndedAt(t *testing.T) {
	t.Parallel()
	i, _ := invocation.New(invocation.NewParams{
		ID: invocIDA, AGID: agidA, PartnerID: partnerIDA, Capability: "x", CorrelationID: correlIDA,
	})
	out := invocation.MarshalAuditEntry(i)
	if !strings.Contains(out, `"ended_at":""`) {
		t.Errorf("ended_at not empty for started invocation: %s", out)
	}
	if strings.Contains(strings.ToLower(out), "gcid") {
		t.Errorf("MarshalAuditEntry contains 'gcid': %s", out)
	}
}

func TestInvocation_RejectsEmptyID(t *testing.T) {
	t.Parallel()
	_, err := invocation.New(invocation.NewParams{
		ID: "", AGID: agidA, PartnerID: partnerIDA, Capability: "x", CorrelationID: correlIDA,
	})
	if err == nil {
		t.Error("expected error for empty ID")
	}
}

func TestInvocation_RejectsEmptyCorrelationID(t *testing.T) {
	t.Parallel()
	_, err := invocation.New(invocation.NewParams{
		ID: invocIDA, AGID: agidA, PartnerID: partnerIDA, Capability: "x", CorrelationID: "",
	})
	if err == nil {
		t.Error("expected error for empty CorrelationID")
	}
}

func TestInvocation_NegativeResponseSize(t *testing.T) {
	t.Parallel()
	i, _ := invocation.New(invocation.NewParams{
		ID: invocIDA, AGID: agidA, PartnerID: partnerIDA, Capability: "x", CorrelationID: correlIDA,
	})
	if err := i.Complete(-1); err == nil {
		t.Error("expected error for negative response size")
	}
}

func TestInvocation_FailedAfterTerminal(t *testing.T) {
	t.Parallel()
	i, _ := invocation.New(invocation.NewParams{
		ID: invocIDA, AGID: agidA, PartnerID: partnerIDA, Capability: "x", CorrelationID: correlIDA,
	})
	_ = i.Fail("ERR")
	if err := i.Fail("ERR2"); err == nil {
		t.Error("expected error failing twice")
	}
	if err := i.Complete(0); err == nil {
		t.Error("expected error completing after fail")
	}
	if err := i.RateLimit(); err == nil {
		t.Error("expected error rate-limiting after fail")
	}
	if err := i.ScopeDeny(""); err == nil {
		t.Error("expected error scope-denying after fail")
	}
}

func TestInvocation_ScopeDeny_DefaultReason(t *testing.T) {
	t.Parallel()
	i, _ := invocation.New(invocation.NewParams{
		ID: invocIDA, AGID: agidA, PartnerID: partnerIDA, Capability: "x", CorrelationID: correlIDA,
	})
	_ = i.ScopeDeny("")
	if i.ErrorCode != "SCOPE_DENIED" {
		t.Errorf("ErrorCode = %q; want SCOPE_DENIED", i.ErrorCode)
	}
}
