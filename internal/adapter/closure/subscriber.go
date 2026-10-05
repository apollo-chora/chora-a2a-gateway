// Package closure wires the AGID-closure subscriber per ADR-132 §10 +
// account-closure-saga skill.
//
// The closure orchestrator (chora-closure-orchestrator) emits
// `chora.closure.requested.v1` events for every account-closure flow. Most
// closures target a GCID (human user); when the closure target is an AGID
// (external agent), this subscriber:
//
//  1. Resolves the AGID → Registration aggregate
//  2. Soft-deletes the registration (terminal state)
//  3. Emits `chora.a2a.agid.revoked.v1` for downstream cache invalidation
//
// AGID closure is fundamentally different from GCID closure: agents have no
// PII, no learning history, no cross-domain projections. The closure is just
// a deactivation + contract-revocation step. There is no per-domain
// pseudonymisation needed for AGID-only data.
//
// CRITICAL invariants (see .claude/rules/ddd-enforcement.md #10):
//   - AGID cannot hold TenantMembership — closure orchestrator's invariant
//     `AGID cannot own a closure saga` already ensures GCID-targeted sagas;
//     this subscriber handles the inverse — explicit AGID-target events.
//   - All actions are idempotent (multiple deliveries → same final state).
//   - Soft-delete only (preserve audit trail).
package closure

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/events"
	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/repo"
	"github.com/apollo-chora/chora-common/idempotent"
)

// AGIDClosureInboxTTL is the dedupe-key retention window for AGID-closure
// redelivery. 24h covers event bus max redelivery for the closure saga's
// typical AGID resolution latency. Production may tune via WithInboxTTL.
const AGIDClosureInboxTTL = 24 * time.Hour

// ClosureRequestedEvent mirrors the saga's chora.closure.requested.v1 payload
// (subset). Real wire format is the closure-orchestrator Protobuf event.
type ClosureRequestedEvent struct {
	SagaID      string
	TargetID    string // GCID or AGID
	TenantID    string
	Reason      string
	Traceparent string
}

// IsAGIDTarget reports whether the closure event targets an AGID rather than
// a GCID. AGIDs are prefixed `agid:` per partner.AGIDPrefix.
func (e ClosureRequestedEvent) IsAGIDTarget() bool {
	return strings.HasPrefix(strings.TrimSpace(e.TargetID), "agid:")
}

// Subscriber consumes closure-saga events and runs AGID-specific closure.
//
// W1.8 (2026-05-12): the soft-delete idempotency (no-op when DeletedAt != nil)
// is now backed by an idempotent.Store inbox to prevent the concurrent-
// redelivery race two replicas would otherwise hit (both read DeletedAt=nil,
// both call SoftDeleteRegistration, both emit revoked events). The inbox
// short-circuits the second call entirely.
type Subscriber struct {
	registrations repo.RegistrationStore
	publisher     events.Publisher
	inbox         idempotent.Store
	ttl           time.Duration
}

// NewSubscriber constructs the AGID-closure subscriber.
//
// inbox is OPTIONAL — nil triggers MemoryStore fallback for backward
// compat. Production callers SHOULD pass a PostgresStore so dedup survives
// pod restart + works across replicas.
func NewSubscriber(regs repo.RegistrationStore, pub events.Publisher, inbox idempotent.Store) *Subscriber {
	if inbox == nil {
		inbox = idempotent.NewMemoryStore()
	}
	return &Subscriber{
		registrations: regs,
		publisher:     pub,
		inbox:         inbox,
		ttl:           AGIDClosureInboxTTL,
	}
}

// WithInboxTTL overrides the default dedupe-key retention window.
func (s *Subscriber) WithInboxTTL(ttl time.Duration) *Subscriber {
	if s == nil || ttl <= 0 {
		return s
	}
	s.ttl = ttl
	return s
}

// HandleClosureRequested processes a single chora.closure.requested.v1 event.
//
// Dedup: keyed on (saga_id :: target_agid) — a duplicate event bus delivery
// (pod restart, multi-replica race, retry-after-ack-window) hits the same
// key + skips the handler body, returning nil.
//
// Returns nil for:
//   - GCID-target closures (ignored — handled by the human-account flow)
//   - Already-soft-deleted registrations (idempotency, defence-in-depth)
//   - Unknown AGIDs (drop with WARN; the saga will time out independently)
//
// Returns an error only on transient infra failures.
func (s *Subscriber) HandleClosureRequested(ctx context.Context, ev ClosureRequestedEvent) error {
	if !ev.IsAGIDTarget() {
		return nil // not our concern
	}
	if strings.TrimSpace(ev.TargetID) == "" {
		return errors.New("closure: empty target_id on AGID-target event")
	}

	key := "agid_closure:" + ev.SagaID + ":" + ev.TargetID
	return s.inbox.Process(ctx, key, s.ttl, func() error {
		reg, err := s.registrations.GetByAGID(ev.TargetID)
		if errors.Is(err, repo.ErrNotFound) {
			// Unknown AGID: still emit a revoked event for downstream caches.
			// The orchestrator's saga will eventually time out and release the
			// reservation; we don't need to surface this as an error.
			_ = s.publisher.Publish(events.Event{
				Topic: "chora.a2a.agid.revoked.v1",
				Payload: map[string]any{
					"agid":    ev.TargetID,
					"saga_id": ev.SagaID,
					"reason":  ev.Reason,
					"unknown": true,
				},
				TenantID:           orPlatform(ev.TenantID),
				Traceparent:        ev.Traceparent,
				IMDADimension:      "accountability",
				IMDALifecycleStage: "runtime",
			})
			return nil
		}
		if err != nil {
			return fmt.Errorf("closure: lookup AGID: %w", err)
		}

		// Defence-in-depth: already soft-deleted → just re-emit the revoked
		// event (inbox should normally short-circuit before reaching here).
		if reg.DeletedAt == nil {
			reg.SoftDeleteRegistration()
			if err := s.registrations.Put(reg); err != nil {
				return fmt.Errorf("closure: persist soft-delete: %w", err)
			}
		}

		return s.publisher.Publish(events.Event{
			Topic: "chora.a2a.agid.revoked.v1",
			Payload: map[string]any{
				"registration_id": reg.ID,
				"agid":            reg.AGID,
				"saga_id":         ev.SagaID,
				"reason":          ev.Reason,
			},
			TenantID:           orPlatform(ev.TenantID),
			Traceparent:        ev.Traceparent,
			IMDADimension:      "accountability",
			IMDALifecycleStage: "runtime",
		})
	})
}

func orPlatform(tenant string) string {
	if strings.TrimSpace(tenant) != "" {
		return tenant
	}
	return "platform"
}
