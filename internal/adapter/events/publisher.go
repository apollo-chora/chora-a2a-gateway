// Package events provides event publishing for chora-a2a-gateway.
//
// In-memory publisher for tests + local dev; production swaps in the
// transactional outbox publisher (internal/adapter/outbox) whose
// dispatcher drains to the NATS JetStream event bus. Topic taxonomy
// stays the same.
//
// CRITICAL invariants per CLAUDE.md §6 + envelope.proto:
//   - Every published event carries the mandatory envelope fields (event_id
//     UUIDv7, idempotency_key, tenant_id, occurred_at, published_at,
//     traceparent, source_project, source_service, schema_version)
//   - Topic format: chora.{domain}.{aggregate}.{event_type}.v{N}
//   - Topics for partner registration / contracts / invocations:
//   - chora.a2a.partner.registered.v1
//   - chora.a2a.partner.approved.v1
//   - chora.a2a.partner.suspended.v1
//   - chora.a2a.partner.reinstated.v1
//   - chora.a2a.partner.revoked.v1
//   - chora.a2a.contract.published.v1
//   - chora.a2a.contract.deprecated.v1
//   - chora.a2a.contract.invoked.v1
//   - chora.a2a.contract.rejected.v1
//   - chora.a2a.agid.registered.v1
//   - chora.a2a.agid.revoked.v1
//   - chora.a2a.dns_txt.verified.v1
//   - chora.a2a.dns_txt.failed.v1
//   - chora.a2a.byoa_key.rotated.v1
//   - chora.a2a.mcp.tool_invoked.v1
//   - chora.a2a.mcp_addon.suspended.v1
//   - chora.a2a.mcp_addon.reinstated.v1
//   - chora.a2a.invocation.started.v1
//   - chora.a2a.invocation.completed.v1
//   - chora.a2a.invocation.failed.v1
package events

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/apollo-chora/chora-common/env"
)

// SourceProject is the source project label stamped on every event
// (CHO-2419). Was a hardcoded literal until 2026-09-02 (CHO-2419). No
// manifest could reach it, so a second org stamped every event with
// chora-local and any consumer filtering on source_project would have been
// filtering on a lie. CHORA_SOURCE_PROJECT is now set on every
// event-emitting service; the literal stays as the fallback so this estate
// is provably unchanged.
var SourceProject = env.GetOrDefault("CHORA_SOURCE_PROJECT", "chora-local")

// SourceService is the OTel + envelope source service name.
const SourceService = "chora-a2a-gateway"

// SchemaVersion is the current event payload schema version.
const SchemaVersion = 1

// knownTopics enumerates the canonical chora.a2a.* topic taxonomy.
//
// The publisher rejects topics that are not in this set so accidental
// drift from the registered schema cannot reach consumers.
var knownTopics = map[string]struct{}{
	"chora.a2a.partner.registered.v1":      {},
	"chora.a2a.partner.approved.v1":        {},
	"chora.a2a.partner.suspended.v1":       {},
	"chora.a2a.partner.reinstated.v1":      {},
	"chora.a2a.partner.revoked.v1":         {},
	"chora.a2a.contract.published.v1":      {},
	"chora.a2a.contract.deprecated.v1":     {},
	"chora.a2a.contract.invoked.v1":        {},
	"chora.a2a.contract.rejected.v1":       {},
	"chora.a2a.agid.registered.v1":         {},
	"chora.a2a.agid.revoked.v1":            {},
	"chora.a2a.dns_txt.verified.v1":        {},
	"chora.a2a.dns_txt.failed.v1":          {},
	"chora.a2a.byoa_key.rotated.v1":        {},
	"chora.a2a.byoa_key.revoked.v1":        {},
	"chora.a2a.mcp.tool_invoked.v1":        {},
	"chora.a2a.mcp_addon.suspended.v1":     {},
	"chora.a2a.mcp_addon.reinstated.v1":    {},
	"chora.a2a.invocation.started.v1":      {},
	"chora.a2a.invocation.completed.v1":    {},
	"chora.a2a.invocation.failed.v1":       {},
	"chora.a2a.invocation.rate_limited.v1": {},
	"chora.a2a.invocation.scope_denied.v1": {},
}

// IsKnownTopic returns true if the topic is in the canonical chora.a2a.*
// taxonomy and matches the chora.{domain}.{aggregate}.{event_type}.v{N}
// shape.
func IsKnownTopic(topic string) bool {
	_, ok := knownTopics[topic]
	return ok
}

// Event is the input shape callers pass to Publisher.Publish.
type Event struct {
	Topic       string
	Payload     map[string]any
	TenantID    string
	GCID        string // empty for system / agent-only events
	Traceparent string
	Tracestate  string

	// IMDADimension is the optional ADR-141 IMDA Model AI Governance
	// canonical label for this event ("accountability" | "transparency"
	// | "safety_and_robustness" | "fairness_and_human_oversight").
	IMDADimension string

	// IMDALifecycleStage is the optional 4-stage IMDA pipeline classifier
	// ("ci_pre_merge" | "pre_deploy" | "runtime" | "post_deploy").
	IMDALifecycleStage string
}

// PublishedEvent is what the publisher snapshot returns — the wire-shape
// envelope plus payload.
type PublishedEvent struct {
	EventID            string
	IdempotencyKey     string
	Topic              string
	TenantID           string
	GCID               string
	OccurredAt         time.Time
	PublishedAt        time.Time
	Traceparent        string
	Tracestate         string
	SourceProject      string
	SourceService      string
	SchemaVersion      int
	Payload            map[string]any
	IMDADimension      string
	IMDALifecycleStage string
}

// Publisher is the chora.a2a.* event publisher port.
type Publisher interface {
	Publish(e Event) error
}

// InMemoryPublisher captures every Publish call in-memory; production
// swaps for the transactional outbox publisher (dispatcher → NATS JetStream).
type InMemoryPublisher struct {
	mu     sync.Mutex
	events []PublishedEvent

	// Now is injectable for tests.
	Now func() time.Time
}

// NewInMemoryPublisher constructs a fresh publisher.
func NewInMemoryPublisher() *InMemoryPublisher {
	return &InMemoryPublisher{Now: func() time.Time { return time.Now().UTC() }}
}

// Publish records the event with a fully-formed envelope.
func (p *InMemoryPublisher) Publish(e Event) error {
	if err := validateTopic(e.Topic); err != nil {
		return err
	}
	if strings.TrimSpace(e.TenantID) == "" {
		return errors.New("publisher: tenant_id required")
	}
	now := time.Now().UTC()
	if p.Now != nil {
		now = p.Now()
	}
	eventID := newUUIDv7()
	idemKey := eventID
	if v, ok := e.Payload["idempotency_key"].(string); ok && v != "" {
		idemKey = v
	}
	pe := PublishedEvent{
		EventID:            eventID,
		IdempotencyKey:     idemKey,
		Topic:              e.Topic,
		TenantID:           e.TenantID,
		GCID:               e.GCID,
		OccurredAt:         now,
		PublishedAt:        now,
		Traceparent:        e.Traceparent,
		Tracestate:         e.Tracestate,
		SourceProject:      SourceProject,
		SourceService:      SourceService,
		SchemaVersion:      SchemaVersion,
		Payload:            e.Payload,
		IMDADimension:      strings.ToLower(strings.TrimSpace(e.IMDADimension)),
		IMDALifecycleStage: strings.ToLower(strings.TrimSpace(e.IMDALifecycleStage)),
	}
	p.mu.Lock()
	p.events = append(p.events, pe)
	p.mu.Unlock()
	return nil
}

// Snapshot returns a copy of the captured events (oldest-first).
func (p *InMemoryPublisher) Snapshot() []PublishedEvent {
	p.mu.Lock()
	defer p.mu.Unlock()
	cp := make([]PublishedEvent, len(p.events))
	copy(cp, p.events)
	return cp
}

// Reset clears the captured events (test helper).
func (p *InMemoryPublisher) Reset() {
	p.mu.Lock()
	p.events = p.events[:0]
	p.mu.Unlock()
}

// validateTopic enforces the chora.{domain}.{aggregate}.{event_type}.v{N}
// taxonomy and rejects topics outside the canonical list.
func validateTopic(t string) error {
	if t == "" {
		return errors.New("publisher: topic required")
	}
	if !strings.HasPrefix(t, "chora.") {
		return fmt.Errorf("publisher: topic %q must start with chora.", t)
	}
	parts := strings.Split(t, ".")
	if len(parts) < 5 {
		return fmt.Errorf("publisher: topic %q malformed; want chora.{domain}.{aggregate}.{event_type}.v{N}", t)
	}
	last := parts[len(parts)-1]
	if !strings.HasPrefix(last, "v") {
		return fmt.Errorf("publisher: topic %q missing version suffix", t)
	}
	if !IsKnownTopic(t) {
		return fmt.Errorf("publisher: topic %q not in canonical chora.a2a.* taxonomy", t)
	}
	return nil
}

func newUUIDv7() string {
	return uuid.Must(uuid.NewV7()).String()
}
