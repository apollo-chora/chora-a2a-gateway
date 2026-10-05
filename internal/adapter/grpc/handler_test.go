// Package grpcadapter_test — handler_test.go: integration tests for the
// production Handler, exercising the same business logic as the REST tests.
package grpcadapter_test

import (
	"context"
	"strings"
	"testing"

	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/events"
	grpcadapter "github.com/apollo-chora/chora-a2a-gateway/internal/adapter/grpc"
	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/rate_limiter"
	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/repo/inmem"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/contract"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/partner"
)

func newHandler(t *testing.T) (*grpcadapter.Handler, *inmem.RegistrationRepo, *inmem.ContractRepo, *inmem.InvocationRepo, *events.InMemoryPublisher, *rate_limiter.TokenBucket) {
	t.Helper()
	regs := inmem.NewRegistrationRepo()
	cons := inmem.NewContractRepo()
	invs := inmem.NewInvocationRepo()
	pub := events.NewInMemoryPublisher()
	rl := rate_limiter.NewTokenBucket()
	h := grpcadapter.NewHandler(grpcadapter.HandlerConfig{
		Registrations: regs, Contracts: cons, Invocations: invs,
		Publisher: pub, RateLimiter: rl,
	})
	return h, regs, cons, invs, pub, rl
}

func seedApprovedPartner(t *testing.T, regs *inmem.RegistrationRepo) (*partner.Registration, string) {
	t.Helper()
	reg, err := partner.NewRegistration(partner.RegistrationParams{
		ID:                 "01970000-0000-7000-a000-000000000001",
		OrgName:            "Acme",
		ContactEmail:       "ops@acme.example",
		Capabilities:       []string{"recommend"},
		RequestedRateLimit: 100,
	})
	if err != nil {
		t.Fatalf("NewRegistration: %v", err)
	}
	res, err := reg.Approve(partner.ApprovalParams{
		ApprovedByGCID: "01970000-0000-7000-9000-000000000001",
		Tier:           partner.TierHigh,
	})
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	_ = regs.Put(reg)
	return reg, res.APIKeyPlaintext
}

func seedContract(t *testing.T, cons *inmem.ContractRepo, partnerID, capName string) {
	t.Helper()
	c, err := contract.New(contract.NewParams{
		ID:         "01970000-0000-7000-d000-000000000001",
		PartnerID:  partnerID,
		AuthMethod: contract.AuthAPIKey,
		Capabilities: []contract.Capability{
			{Name: capName, Tier: contract.TierHigh, RateLimitPerMin: 600},
		},
	})
	if err != nil {
		t.Fatalf("contract.New: %v", err)
	}
	_ = cons.Put(c)
}

func TestHandler_Invoke_HappyPath(t *testing.T) {
	t.Parallel()
	h, regs, cons, _, pub, rl := newHandler(t)
	reg, key := seedApprovedPartner(t, regs)
	seedContract(t, cons, reg.ID, "recommend_content")
	rl.Configure(reg.AGID, rate_limiter.Policy{RatePerMinute: 600, Burst: 10})

	resp, err := h.Invoke(context.Background(), &grpcadapter.InvokeRequest{
		PartnerID:     reg.ID,
		APIKey:        key,
		Capability:    "recommend_content",
		CorrelationID: "01970000-0000-7000-c000-000000000001",
		TenantID:      "tenant-1",
	})
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if resp.Status != "completed" {
		t.Errorf("Status = %q", resp.Status)
	}
	if resp.ContractVersion != 1 {
		t.Errorf("ContractVersion = %d", resp.ContractVersion)
	}
	snap := pub.Snapshot()
	if len(snap) == 0 || snap[0].Topic != "chora.a2a.invocation.completed.v1" {
		t.Errorf("topic = %v", snap)
	}
	// Must NOT have leaked the GCID into the audit body.
	for _, e := range snap {
		if v, ok := e.Payload["gcid"]; ok {
			s, _ := v.(string)
			if strings.HasPrefix(s, "agid:") {
				t.Errorf("AGID leaked into gcid: %v", e.Payload)
			}
		}
	}
}

func TestHandler_Invoke_RejectsBadAPIKey(t *testing.T) {
	t.Parallel()
	h, regs, cons, _, _, rl := newHandler(t)
	reg, _ := seedApprovedPartner(t, regs)
	seedContract(t, cons, reg.ID, "recommend_content")
	rl.Configure(reg.AGID, rate_limiter.Policy{RatePerMinute: 600, Burst: 10})

	_, err := h.Invoke(context.Background(), &grpcadapter.InvokeRequest{
		PartnerID:     reg.ID,
		APIKey:        "bad-key",
		Capability:    "recommend_content",
		CorrelationID: "01970000-0000-7000-c000-000000000099",
	})
	if err == nil || !strings.Contains(err.Error(), "INVALID_API_KEY") {
		t.Errorf("expected INVALID_API_KEY; got %v", err)
	}
}

// Exercise the rate_limited branch: burst-1 bucket means a second, immediate
// Invoke for the same AGID is denied and surfaced as RATE_LIMITED (not an
// error — a structured response carrying the invocation id).
func TestHandler_Invoke_RateLimited(t *testing.T) {
	t.Parallel()
	h, regs, cons, _, pub, rl := newHandler(t)
	reg, key := seedApprovedPartner(t, regs)
	seedContract(t, cons, reg.ID, "recommend_content")
	rl.Configure(reg.AGID, rate_limiter.Policy{RatePerMinute: 600, Burst: 1}) // single token

	call := func(corr string) (*grpcadapter.InvokeResponse, error) {
		return h.Invoke(context.Background(), &grpcadapter.InvokeRequest{
			PartnerID: reg.ID, APIKey: key, Capability: "recommend_content",
			CorrelationID: corr,
		})
	}

	if _, err := call("01970000-0000-7000-c000-0000000000aa"); err != nil {
		t.Fatalf("first invoke: %v", err)
	}
	resp, err := call("01970000-0000-7000-c000-0000000000ab")
	if err != nil {
		t.Fatalf("second invoke: %v", err)
	}
	if resp.Status != "rate_limited" || resp.ErrorCode != "RATE_LIMITED" {
		t.Errorf("resp = %+v; want rate_limited", resp)
	}
	if resp.InvocationID == "" {
		t.Error("rate-limited response must carry an invocation id")
	}
	foundRateLimited := false
	for _, e := range pub.Snapshot() {
		if e.Topic == "chora.a2a.invocation.rate_limited.v1" {
			foundRateLimited = true
			break
		}
	}
	if !foundRateLimited {
		t.Errorf("expected rate_limited audit event; got %v", pub.Snapshot())
	}
}

func TestHandler_Invoke_RejectsSuspendedPartner(t *testing.T) {
	t.Parallel()
	h, regs, cons, _, _, rl := newHandler(t)
	reg, key := seedApprovedPartner(t, regs)
	seedContract(t, cons, reg.ID, "recommend_content")
	rl.Configure(reg.AGID, rate_limiter.Policy{RatePerMinute: 600, Burst: 10})

	_ = reg.SuspendRegistration("policy_violation", "01970000-0000-7000-9000-000000000001")
	_ = regs.Put(reg)

	_, err := h.Invoke(context.Background(), &grpcadapter.InvokeRequest{
		PartnerID:     reg.ID,
		APIKey:        key,
		Capability:    "recommend_content",
		CorrelationID: "01970000-0000-7000-c000-000000000088",
	})
	if err == nil || !strings.Contains(err.Error(), "PARTNER_SUSPENDED") {
		t.Errorf("expected PARTNER_SUSPENDED; got %v", err)
	}
}

func TestHandler_Invoke_ScopeDenied(t *testing.T) {
	t.Parallel()
	h, regs, cons, _, pub, rl := newHandler(t)
	reg, key := seedApprovedPartner(t, regs)
	seedContract(t, cons, reg.ID, "recommend_content")
	rl.Configure(reg.AGID, rate_limiter.Policy{RatePerMinute: 600, Burst: 10})

	resp, err := h.Invoke(context.Background(), &grpcadapter.InvokeRequest{
		PartnerID:     reg.ID,
		APIKey:        key,
		Capability:    "write_persona_memory",
		CorrelationID: "01970000-0000-7000-c000-000000000077",
	})
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if resp.Status != "scope_denied" {
		t.Errorf("Status = %q", resp.Status)
	}
	last := pub.Snapshot()[len(pub.Snapshot())-1]
	if last.Topic != "chora.a2a.invocation.scope_denied.v1" {
		t.Errorf("topic = %q", last.Topic)
	}
}

func TestHandler_GetContract_HappyPath(t *testing.T) {
	t.Parallel()
	h, regs, cons, _, _, _ := newHandler(t)
	reg, _ := seedApprovedPartner(t, regs)
	seedContract(t, cons, reg.ID, "recommend_content")
	resp, err := h.GetContract(context.Background(), &grpcadapter.GetContractRequest{
		PartnerID: reg.ID,
	})
	if err != nil {
		t.Fatalf("GetContract: %v", err)
	}
	if resp.AuthMethod != "api_key" {
		t.Errorf("AuthMethod = %q", resp.AuthMethod)
	}
	if len(resp.Capabilities) != 1 {
		t.Errorf("Capabilities len = %d", len(resp.Capabilities))
	}
}

func TestHandler_GetContract_NoActive(t *testing.T) {
	t.Parallel()
	h, _, _, _, _, _ := newHandler(t)
	_, err := h.GetContract(context.Background(), &grpcadapter.GetContractRequest{PartnerID: "absent"})
	if err == nil {
		t.Error("expected error for partner with no contracts")
	}
}
