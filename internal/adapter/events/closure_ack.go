// ClosureAckPublisher — eventbus implementation of the per-domain
// ClosurePublisher port used by the closure subscriber (CHO-1719 gap 4).
//
// Projects the port call onto the canonical envelope (envelope.Build) +
// the eventbus publisher (NATS JetStream in production, in-memory bus in
// dev/tests).
//
// Delivery note: acks publish DIRECTLY to the bus (not via the per-domain
// outbox). The publish happens inside the subscriber's idempotent
// inbox.Process closure — a failed publish errors Handle, the subscriber
// nacks, and the bus redelivers; the orchestrator's ack recording is
// idempotent on the deterministic idempotency key below, so
// at-least-once is safe.
package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/apollo-chora/chora-common/envelope"
	"github.com/apollo-chora/chora-common/eventbus"
)

// BusClosureAckPublisher publishes closure-saga acks on
// chora.{domain}.account.pseudonymised.v1 (and the failed variant).
type BusClosureAckPublisher struct {
	inner         eventbus.Publisher
	sourceProject string
	sourceService string
}

// NewBusClosureAckPublisher wraps an eventbus.Publisher.
func NewBusClosureAckPublisher(
	inner eventbus.Publisher, sourceProject, sourceService string,
) *BusClosureAckPublisher {
	return &BusClosureAckPublisher{
		inner:         inner,
		sourceProject: sourceProject,
		sourceService: sourceService,
	}
}

// Publish satisfies the ClosurePublisher port.
func (p *BusClosureAckPublisher) Publish(
	topic, tenantID, gcid, traceparent string,
	payload map[string]interface{},
) error {
	if p == nil || p.inner == nil {
		return errors.New("events: BusClosureAckPublisher not initialised")
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("events: closure ack payload encode: %w", err)
	}

	env := envelope.Build(context.Background(), envelope.BuildOpts{
		SourceProject:      p.sourceProject,
		SourceService:      p.sourceService,
		SchemaVersion:      1,
		ChoraImdaDimension: "accountability",
		ImdaLifecycleStage: "runtime",
	})
	env.TenantID = tenantID
	env.GCID = gcid
	if traceparent != "" {
		env.Traceparent = traceparent
	}
	// Deterministic idempotency key — a redelivered request re-acks with
	// the same key; the orchestrator collapses duplicates.
	if sid, ok := payload["saga_id"].(string); ok && sid != "" && gcid != "" {
		env.IdempotencyKey = "pseudonymise_ack:" + sid + ":" + gcid
	}

	return p.inner.Publish(context.Background(), topic, env, body)
}
