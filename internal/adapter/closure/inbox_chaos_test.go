// Package closure_test — chaos-readiness tests for the W1.8 closure
// subscriber inbox swap (2026-05-12, the SECOND closure path on the
// a2a-gateway alongside events/closure_subscriber.go).
//
// Verifies the Store-backed dedup prevents the concurrent-redelivery race
// two replicas would otherwise hit. 4 scenarios mirror W1.7 +
// W1.8a/b/c canonical pattern:
//
//  1. SurvivesRecreation — same Store survives Subscriber recreation
//  2. FreshStoreReprocesses — per-subscriber Stores fail (negative control)
//  3. ConcurrentReplicas — multi-pod race against the same Store
//  4. TTLExpiryReprocesses — re-processes after dedup-key retention window
//
// Production wires PostgresStore so these properties hold across real
// pod-death + multi-replica deployment.
package closure_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/closure"
	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/events"
	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/repo/inmem"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/partner"
	"github.com/apollo-chora/chora-common/idempotent"
)

func seedRegistrationForChaos(t *testing.T, regs *inmem.RegistrationRepo) string {
	t.Helper()
	reg, _ := partner.NewRegistration(partner.RegistrationParams{
		ID:                 "01970000-0000-7000-b000-cccccccccccc",
		OrgName:            "Chaos",
		ContactEmail:       "chaos@example.com",
		Capabilities:       []string{"recommend"},
		RequestedRateLimit: 60,
	})
	_, _ = reg.Approve(partner.ApprovalParams{ApprovedByGCID: gcid, Tier: partner.TierLow})
	reg.AGID = agid
	_ = regs.Put(reg)
	return agid
}

func TestSubscriber_InboxSurvivesRecreation(t *testing.T) {
	t.Parallel()
	regs := inmem.NewRegistrationRepo()
	pub := events.NewInMemoryPublisher()
	agidTarget := seedRegistrationForChaos(t, regs)
	inbox := idempotent.NewMemoryStore()

	s1 := closure.NewSubscriber(regs, pub, inbox)
	ev := closure.ClosureRequestedEvent{SagaID: "saga-chaos-1", TargetID: agidTarget, TenantID: "t1"}
	if err := s1.HandleClosureRequested(context.Background(), ev); err != nil {
		t.Fatalf("first delivery on s1: %v", err)
	}

	// Simulate pod restart: recreate s2 with the SAME inbox.
	s2 := closure.NewSubscriber(regs, pub, inbox)
	if err := s2.HandleClosureRequested(context.Background(), ev); err != nil {
		t.Fatalf("redelivery on s2 (post-restart): %v", err)
	}

	if got := len(pub.Snapshot()); got != 1 {
		t.Errorf("expected 1 revoked emission across pod-restart; got %d", got)
	}
}

func TestSubscriber_InboxFreshStoreReprocesses(t *testing.T) {
	t.Parallel()
	// Negative control: per-subscriber fresh inboxes fail to dedup.
	// Soft-delete idempotency in the handler body short-circuits the
	// second soft-delete, but the revoked event is re-emitted because
	// the inbox didn't catch it first.
	regs := inmem.NewRegistrationRepo()
	pub := events.NewInMemoryPublisher()
	agidTarget := seedRegistrationForChaos(t, regs)

	s1 := closure.NewSubscriber(regs, pub, idempotent.NewMemoryStore())
	s2 := closure.NewSubscriber(regs, pub, idempotent.NewMemoryStore())
	ev := closure.ClosureRequestedEvent{SagaID: "saga-chaos-2", TargetID: agidTarget, TenantID: "t1"}

	if err := s1.HandleClosureRequested(context.Background(), ev); err != nil {
		t.Fatalf("s1: %v", err)
	}
	if err := s2.HandleClosureRequested(context.Background(), ev); err != nil {
		t.Fatalf("s2 (fresh inbox): %v", err)
	}
	if got := len(pub.Snapshot()); got != 2 {
		t.Errorf("FRESH-store negative control: expected 2 emissions (no shared dedup); got %d", got)
	}
}

func TestSubscriber_InboxConcurrentReplicas(t *testing.T) {
	t.Parallel()
	regs := inmem.NewRegistrationRepo()
	pub := events.NewInMemoryPublisher()
	agidTarget := seedRegistrationForChaos(t, regs)
	inbox := idempotent.NewMemoryStore()

	sA := closure.NewSubscriber(regs, pub, inbox)
	sB := closure.NewSubscriber(regs, pub, inbox)
	ev := closure.ClosureRequestedEvent{SagaID: "saga-chaos-3", TargetID: agidTarget, TenantID: "t1"}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _ = sA.HandleClosureRequested(context.Background(), ev) }()
	go func() { defer wg.Done(); _ = sB.HandleClosureRequested(context.Background(), ev) }()
	wg.Wait()

	if got := len(pub.Snapshot()); got != 1 {
		t.Fatalf("multi-replica: expected exactly 1 revoked emission; got %d", got)
	}
}

func TestSubscriber_InboxTTLExpiryReprocesses(t *testing.T) {
	t.Parallel()
	regs := inmem.NewRegistrationRepo()
	pub := events.NewInMemoryPublisher()
	agidTarget := seedRegistrationForChaos(t, regs)
	inbox := idempotent.NewMemoryStore()

	s := closure.NewSubscriber(regs, pub, inbox).WithInboxTTL(50 * time.Millisecond)
	ev := closure.ClosureRequestedEvent{SagaID: "saga-chaos-4", TargetID: agidTarget, TenantID: "t1"}

	if err := s.HandleClosureRequested(context.Background(), ev); err != nil {
		t.Fatalf("first handle: %v", err)
	}
	inbox.Advance(100 * time.Millisecond)
	if err := s.HandleClosureRequested(context.Background(), ev); err != nil {
		t.Fatalf("second handle (post-TTL): %v", err)
	}
	// Post-TTL reprocesses → emits a 2nd revoked event.
	if got := len(pub.Snapshot()); got != 2 {
		t.Errorf("TTL-expiry: expected 2 emissions; got %d", got)
	}
}
