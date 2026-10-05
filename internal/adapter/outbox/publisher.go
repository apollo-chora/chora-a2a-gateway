// Package outbox — TransactionalOutboxPublisher implementation.
//
// TransactionalOutboxPublisher satisfies the existing
// events.Publisher interface (Publish(e events.Event) error) by writing
// the event to the a2a_outbox_events table instead of publishing
// directly to the event bus. The Dispatcher (see dispatcher.go) drains the
// table to the NATS JetStream event bus on a separate goroutine. This
// decouples event emission from bus availability — a crash between the
// domain-state write and the publish no longer loses events.
//
// The on-wire payload + envelope keys are intentionally identical to the
// legacy InMemoryPublisher so subscribers see the same fields whether
// they receive from the legacy direct-publish path or the new outbox
// path. Migration is a constructor swap in main().
//
// Per `feedback_d6_resilience_first_class` B.6.2.a producer-side durable
// emission for chora-a2a-gateway's chora.a2a.* event streams.
package outbox

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	cgctracing "github.com/apollo-chora/chora-common/tracing"

	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/events"
	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/outbox/protomarshal"
)

// schemaVersion is the major version of the on-wire payload schema.
// Matches the v{N} suffix in chora.a2a.*.v{N} topics.
const schemaVersion = 1

// PublisherConfig wires the TransactionalOutboxPublisher.
type PublisherConfig struct {
	// Store is the outbox table backend. Required.
	Store Store

	// SourceProject is the source project label stamped on every event
	// (CHO-2419). Defaults to "chora-local".
	SourceProject string

	// SourceService is the publisher's service name. Defaults to
	// "chora-a2a-gateway".
	SourceService string

	// Now is injectable for tests; defaults to time.Now().UTC.
	Now func() time.Time
}

// Publisher satisfies the existing events.Publisher interface by
// enqueueing the event into a2a_outbox_events.
type Publisher struct {
	cfg PublisherConfig
}

// NewPublisher constructs a TransactionalOutboxPublisher.
func NewPublisher(cfg PublisherConfig) *Publisher {
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	if cfg.SourceProject == "" {
		cfg.SourceProject = "chora-local"
	}
	if cfg.SourceService == "" {
		cfg.SourceService = "chora-a2a-gateway"
	}
	return &Publisher{cfg: cfg}
}

// Publish satisfies events.Publisher. Writes the event as a pending row in
// a2a_outbox_events. The Dispatcher publishes to the event bus asynchronously.
func (p *Publisher) Publish(e events.Event) error {
	if p.cfg.Store == nil {
		return fmt.Errorf("outbox: store not wired")
	}
	if err := validateTopic(e.Topic); err != nil {
		return err
	}
	if strings.TrimSpace(e.TenantID) == "" {
		return fmt.Errorf("outbox: tenant_id required")
	}

	now := p.cfg.Now()

	// Mint an event_id (UUIDv7) for the envelope.
	eventID := newUUIDv7()

	// idempotency_key: prefer payload override (caller-provided stable key
	// e.g. aggregate_id + version) over the random event_id default.
	idemKey := eventID
	if e.Payload != nil {
		if v, ok := e.Payload["idempotency_key"].(string); ok && v != "" {
			idemKey = v
		}
	}

	// agid: extract from payload for the a2a_outbox_events.agid column.
	// Many chora.a2a.* events carry an AGID in their payload (caller agent
	// identity) — the column makes that queryable for D6.3 isolation.
	agid := ""
	if e.Payload != nil {
		if v, ok := e.Payload["agid"].(string); ok {
			agid = v
		}
	}

	// Build the envelope as a flat string map for the JSONB column. This
	// is the on-wire attribute set published to the event bus (subscribers
	// can filter without parsing the payload).
	traceparent := cgctracing.EnsureTraceparent(e.Traceparent)
	envelope := map[string]string{
		"event_id":             eventID,
		"idempotency_key":      idemKey,
		"tenant_id":            e.TenantID,
		"gcid":                 e.GCID,
		"occurred_at":          now.Format(time.RFC3339Nano),
		"published_at":         now.Format(time.RFC3339Nano),
		"traceparent":          traceparent,
		"tracestate":           e.Tracestate,
		"source_project":       p.cfg.SourceProject,
		"source_service":       p.cfg.SourceService,
		"schema_version":       strconv.Itoa(schemaVersion),
		"chora_imda_dimension": canonicaliseLower(e.IMDADimension),
		"imda_lifecycle_stage": canonicaliseLower(e.IMDALifecycleStage),
		"agid":                 agid,
	}

	// Producer-side encoding: emit canonical binary protobuf for topics with
	// a registered binary encoder (chora-contracts events-flat schemas);
	// topics without one fall back to JSON with a one-shot WARN.
	pmEnv := protomarshal.Envelope{
		EventID:        eventID,
		IdempotencyKey: idemKey,
		TenantID:       e.TenantID,
		GCID:           e.GCID,
		OccurredAt:     now,
		PublishedAt:    now,
		Traceparent:    traceparent,
		Tracestate:     e.Tracestate,
		SourceProject:  p.cfg.SourceProject,
		SourceService:  p.cfg.SourceService,
		SchemaVersion:  schemaVersion,
	}
	payloadBytes, err := encodePayload(e.Topic, pmEnv, e.Payload)
	if err != nil {
		return fmt.Errorf("outbox: marshal payload: %w", err)
	}

	row := Row{
		ID:             eventID,
		TenantID:       e.TenantID,
		GCID:           e.GCID,
		AGID:           agid,
		EventType:      eventTypeFromTopic(e.Topic),
		Topic:          e.Topic,
		Payload:        payloadBytes,
		Envelope:       envelope,
		IdempotencyKey: idemKey,
		OccurredAt:     now,
	}
	// Insert uses Background context here because events.Publisher.Publish()
	// takes no context. The legacy events.InMemoryPublisher had the same
	// shape; M14 introduces a context-carrying Publisher upgrade.
	return p.cfg.Store.Insert(context.Background(), row)
}

// validateTopic enforces the canonical chora.a2a.* taxonomy via the
// existing events.IsKnownTopic registry — keeps the topic list in one
// source of truth.
func validateTopic(t string) error {
	if t == "" {
		return fmt.Errorf("outbox: topic required")
	}
	if !strings.HasPrefix(t, "chora.") {
		return fmt.Errorf("outbox: topic %q must start with chora.", t)
	}
	parts := strings.Split(t, ".")
	if len(parts) < 5 {
		return fmt.Errorf("outbox: topic %q malformed; want chora.{domain}.{aggregate}.{event_type}.v{N}", t)
	}
	last := parts[len(parts)-1]
	if !strings.HasPrefix(last, "v") {
		return fmt.Errorf("outbox: topic %q missing version suffix", t)
	}
	if !events.IsKnownTopic(t) {
		return fmt.Errorf("outbox: topic %q not in canonical chora.a2a.* taxonomy", t)
	}
	return nil
}

// eventTypeFromTopic derives a stable event_type from the topic name. Topic
// shape: chora.{domain}.{aggregate}.{event_type}.v{N} → event_type =
// "{domain}.{aggregate}.{event_type}".
func eventTypeFromTopic(topic string) string {
	parts := strings.Split(topic, ".")
	if len(parts) < 5 {
		return topic
	}
	// Drop leading "chora" and trailing "v{N}"; join the rest.
	return strings.Join(parts[1:len(parts)-1], ".")
}

// canonicaliseLower trims + lowercases an optional vocab string (used for
// IMDA dimension + lifecycle_stage so the wire-shape stays canonical).
func canonicaliseLower(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func newUUIDv7() string {
	return uuid.Must(uuid.NewV7()).String()
}

// Compile-time port assertion: TransactionalOutboxPublisher satisfies the
// existing events.Publisher interface.
var _ events.Publisher = (*Publisher)(nil)

// -----------------------------------------------------------------------------
// Payload encoding — binary protobuf for topics with a registered encoder,
// JSON fallback for topics that don't yet have one. New topics MUST
// add a case in internal/adapter/outbox/protomarshal/MarshalPayload.
// -----------------------------------------------------------------------------

var (
	warnedUnknownTopicsMu sync.Mutex
	warnedUnknownTopics   = map[string]bool{}
)

func encodePayload(topic string, env protomarshal.Envelope, payload map[string]any) ([]byte, error) {
	bz, err := protomarshal.MarshalPayload(topic, env, payload)
	if err == nil {
		return bz, nil
	}
	if !protomarshal.IsUnsupportedTopic(err) {
		return nil, err
	}

	// Topic not yet wired for binary protobuf. Log a one-shot WARN and fall
	// back to JSON so the pre-existing path doesn't regress. Topics WITHOUT
	// a registered encoder (e.g. chora.a2a.partner.*, chora.a2a.byoa_key.*,
	// chora.a2a.mcp.*) publish fine on the JSON fallback today.
	warnedUnknownTopicsMu.Lock()
	if !warnedUnknownTopics[topic] {
		warnedUnknownTopics[topic] = true
		log.Printf("WARN outbox.publisher: topic %q has no binary protobuf encoder — payload will JSON-marshal. Add a case to internal/adapter/outbox/protomarshal/MarshalPayload if this topic needs canonical binary wire bytes.", topic)
	}
	warnedUnknownTopicsMu.Unlock()

	jb, jErr := json.Marshal(payload)
	if jErr != nil {
		return nil, fmt.Errorf("outbox.publisher: json fallback marshal: %w", jErr)
	}
	return jb, nil
}
