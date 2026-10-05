// Package events_test exercises the in-memory event publisher used by HTTP
// handlers to emit chora.a2a.* envelopes. Real impl in M12 will swap this
// for a event bus publisher backed by Protobuf Schema Registry.
//
// CRITICAL invariants per CLAUDE.md §6 + envelope.proto:
//   - Every published event carries the mandatory envelope fields
//     (event_id, idempotency_key, tenant_id, occurred_at, published_at,
//     traceparent, source_project, source_service, schema_version)
//   - Topic format chora.{domain}.{aggregate}.{event_type}.v{N}
//   - Topics for partner registration:
//   - chora.a2a.partner.registered.v1
//   - chora.a2a.partner.approved.v1
//   - chora.a2a.partner.suspended.v1
//   - chora.a2a.invocation.completed.v1
//
// TDD RED phase — implementation does NOT yet exist.
package events_test

import (
	"strings"
	"testing"

	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/events"
)

func TestInMemoryPublisher_PublishEnvelopeFieldsPresent(t *testing.T) {
	t.Parallel()
	p := events.NewInMemoryPublisher()
	err := p.Publish(events.Event{
		Topic: "chora.a2a.partner.registered.v1",
		Payload: map[string]any{
			"partner_id": "01970000-0000-7000-a000-000000000001",
		},
		TenantID: "platform",
	})
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	got := p.Snapshot()
	if len(got) != 1 {
		t.Fatalf("snapshot len = %d; want 1", len(got))
	}
	e := got[0]
	if e.EventID == "" {
		t.Error("EventID empty; envelope mandatory")
	}
	if e.IdempotencyKey == "" {
		t.Error("IdempotencyKey empty; envelope mandatory")
	}
	if e.TenantID != "platform" {
		t.Errorf("TenantID = %q", e.TenantID)
	}
	if e.OccurredAt.IsZero() {
		t.Error("OccurredAt zero")
	}
	if e.PublishedAt.IsZero() {
		t.Error("PublishedAt zero")
	}
	if e.SourceService != "chora-a2a-gateway" {
		t.Errorf("SourceService = %q", e.SourceService)
	}
	if e.SourceProject == "" {
		t.Error("SourceProject empty")
	}
	if e.SchemaVersion < 1 {
		t.Errorf("SchemaVersion = %d; want >= 1", e.SchemaVersion)
	}
}

func TestPublisher_TopicTaxonomyEnforced(t *testing.T) {
	t.Parallel()
	p := events.NewInMemoryPublisher()
	if err := p.Publish(events.Event{Topic: "bogus", TenantID: "t"}); err == nil {
		t.Error("expected error for malformed topic; got nil")
	}
	if err := p.Publish(events.Event{Topic: "", TenantID: "t"}); err == nil {
		t.Error("expected error for empty topic; got nil")
	}
}

func TestPublisher_RequiresTenantID(t *testing.T) {
	t.Parallel()
	p := events.NewInMemoryPublisher()
	if err := p.Publish(events.Event{
		Topic:    "chora.a2a.partner.registered.v1",
		TenantID: "",
	}); err == nil {
		t.Error("expected error for empty TenantID; got nil")
	}
}

func TestPublisher_PropagatesTraceparent(t *testing.T) {
	t.Parallel()
	p := events.NewInMemoryPublisher()
	tp := "00-0af7651916cd43dd8448eb211c80319c-b9c7c989f97918e1-01"
	_ = p.Publish(events.Event{
		Topic:       "chora.a2a.invocation.completed.v1",
		Payload:     map[string]any{"k": "v"},
		TenantID:    "platform",
		Traceparent: tp,
	})
	got := p.Snapshot()
	if got[0].Traceparent != tp {
		t.Errorf("Traceparent = %q; want %q", got[0].Traceparent, tp)
	}
}

func TestKnownTopics(t *testing.T) {
	t.Parallel()
	want := []string{
		"chora.a2a.partner.registered.v1",
		"chora.a2a.partner.approved.v1",
		"chora.a2a.partner.suspended.v1",
		"chora.a2a.invocation.completed.v1",
	}
	for _, topic := range want {
		if !strings.HasPrefix(topic, "chora.a2a.") {
			t.Errorf("topic %q lacks chora.a2a prefix", topic)
		}
		if !events.IsKnownTopic(topic) {
			t.Errorf("topic %q not recognised", topic)
		}
	}
}
