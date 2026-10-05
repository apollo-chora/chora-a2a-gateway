// Package outbox_test — TransactionalOutboxPublisher adapter tests.
//
// TransactionalOutboxPublisher satisfies the existing
// events.Publisher interface by writing every chora.a2a.* event to the
// a2a_outbox_events table (via the Store port) instead of publishing
// directly to event bus. A separate Dispatcher drains the outbox to Cloud
// event bus. This decouples emission from event bus availability: a crash
// between the domain-state write and the publish no longer loses events
// because the row is durably committed to chora_a2a before the HTTP
// request returns.
//
// Per `feedback_d6_resilience_first_class` B.6.2.a — producer-side
// durable emission for chora-a2a-gateway's chora.a2a.* streams.
package outbox_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/events"
	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/outbox"
)

func TestOutboxPublisher_Publish_WritesRowToStore(t *testing.T) {
	t.Parallel()
	store := outbox.NewInMemoryStore()
	pub := outbox.NewPublisher(outbox.PublisherConfig{
		Store:         store,
		SourceProject: "chora-local",
		SourceService: "chora-a2a-gateway",
	})

	err := pub.Publish(events.Event{
		Topic: "chora.a2a.partner.registered.v1",
		Payload: map[string]any{
			"partner_id": "01970000-0000-7000-a000-000000000001",
		},
		TenantID:    "00000000-0000-0000-0000-0000000000aa",
		GCID:        "00000000-0000-0000-0000-0000000000bb",
		Traceparent: "00-deadbeefdeadbeefdeadbeefdeadbeef-1111111122222222-01",
	})
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	rows, _ := store.FetchPending(context.Background(), 10)
	if len(rows) != 1 {
		t.Fatalf("store rows = %d; want 1", len(rows))
	}
	row := rows[0]
	if row.Topic != "chora.a2a.partner.registered.v1" {
		t.Errorf("row.Topic = %q; want chora.a2a.partner.registered.v1", row.Topic)
	}
	if row.TenantID != "00000000-0000-0000-0000-0000000000aa" {
		t.Errorf("row.TenantID = %q", row.TenantID)
	}
	if row.GCID != "00000000-0000-0000-0000-0000000000bb" {
		t.Errorf("row.GCID = %q", row.GCID)
	}
	if row.IdempotencyKey == "" {
		t.Errorf("row.IdempotencyKey empty")
	}
	if row.EventType == "" {
		t.Errorf("row.EventType empty")
	}
}

func TestOutboxPublisher_Publish_StampsEnvelopeFields(t *testing.T) {
	t.Parallel()
	store := outbox.NewInMemoryStore()
	now := time.Date(2026, 5, 12, 10, 0, 0, 0, time.UTC)
	pub := outbox.NewPublisher(outbox.PublisherConfig{
		Store:         store,
		SourceProject: "chora-local",
		SourceService: "chora-a2a-gateway",
		Now:           func() time.Time { return now },
	})
	err := pub.Publish(events.Event{
		Topic:       "chora.a2a.invocation.completed.v1",
		Payload:     map[string]any{"invocation_id": "inv-1"},
		TenantID:    "00000000-0000-0000-0000-0000000000aa",
		Traceparent: "00-deadbeefdeadbeefdeadbeefdeadbeef-1111111122222222-01",
		Tracestate:  "ts=value",
	})
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	rows, _ := store.FetchPending(context.Background(), 1)
	if len(rows) != 1 {
		t.Fatalf("rows = %d; want 1", len(rows))
	}
	env := rows[0].Envelope

	for _, key := range []string{
		"event_id", "idempotency_key", "tenant_id", "occurred_at", "published_at",
		"traceparent", "source_project", "source_service", "schema_version",
	} {
		if env[key] == "" {
			t.Errorf("envelope.%s empty; want non-empty (mandatory per CLAUDE.md §6)", key)
		}
	}
	if env["source_project"] != "chora-local" {
		t.Errorf("envelope.source_project = %q; want chora-local", env["source_project"])
	}
	if env["source_service"] != "chora-a2a-gateway" {
		t.Errorf("envelope.source_service = %q; want chora-a2a-gateway", env["source_service"])
	}
	if env["schema_version"] != "1" {
		t.Errorf("envelope.schema_version = %q; want 1", env["schema_version"])
	}
	if env["tenant_id"] != "00000000-0000-0000-0000-0000000000aa" {
		t.Errorf("envelope.tenant_id = %q", env["tenant_id"])
	}
	if env["tracestate"] != "ts=value" {
		t.Errorf("envelope.tracestate = %q; want ts=value", env["tracestate"])
	}
	if env["traceparent"] != "00-deadbeefdeadbeefdeadbeefdeadbeef-1111111122222222-01" {
		t.Errorf("envelope.traceparent = %q", env["traceparent"])
	}
}

func TestOutboxPublisher_Publish_RejectsUnknownTopic(t *testing.T) {
	t.Parallel()
	pub := outbox.NewPublisher(outbox.PublisherConfig{Store: outbox.NewInMemoryStore()})
	err := pub.Publish(events.Event{
		Topic:    "chora.a2a.bogus.event.v1",
		TenantID: "t",
	})
	if err == nil {
		t.Errorf("Publish(bogus topic) err = nil; want error")
	}
}

func TestOutboxPublisher_Publish_RejectsEmptyTopic(t *testing.T) {
	t.Parallel()
	pub := outbox.NewPublisher(outbox.PublisherConfig{Store: outbox.NewInMemoryStore()})
	err := pub.Publish(events.Event{Topic: "", TenantID: "t"})
	if err == nil {
		t.Errorf("Publish(empty topic) err = nil; want error")
	}
}

func TestOutboxPublisher_Publish_RejectsMissingStore(t *testing.T) {
	t.Parallel()
	pub := outbox.NewPublisher(outbox.PublisherConfig{})
	err := pub.Publish(events.Event{
		Topic:    "chora.a2a.partner.registered.v1",
		TenantID: "00000000-0000-0000-0000-0000000000aa",
	})
	if err == nil {
		t.Errorf("Publish without store = nil err; want error")
	}
}

func TestOutboxPublisher_Publish_RequiresTenantID(t *testing.T) {
	t.Parallel()
	pub := outbox.NewPublisher(outbox.PublisherConfig{Store: outbox.NewInMemoryStore()})
	err := pub.Publish(events.Event{
		Topic:    "chora.a2a.partner.registered.v1",
		TenantID: "",
	})
	if err == nil {
		t.Errorf("Publish without tenant_id = nil err; want error")
	}
}

func TestOutboxPublisher_Publish_PayloadIsJSONOfEventPayload(t *testing.T) {
	t.Parallel()
	store := outbox.NewInMemoryStore()
	pub := outbox.NewPublisher(outbox.PublisherConfig{Store: store, SourceProject: "chora-local"})
	err := pub.Publish(events.Event{
		Topic: "chora.a2a.contract.invoked.v1",
		Payload: map[string]any{
			"contract_id": "ctx-1",
			"caller_agid": "agid-x",
			"verdict":     "approved",
		},
		TenantID: "00000000-0000-0000-0000-0000000000aa",
	})
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	rows, _ := store.FetchPending(context.Background(), 1)
	if len(rows) != 1 {
		t.Fatalf("rows = %d; want 1", len(rows))
	}
	var pl map[string]any
	if err := json.Unmarshal(rows[0].Payload, &pl); err != nil {
		t.Fatalf("payload not JSON: %v (%s)", err, string(rows[0].Payload))
	}
	if pl["contract_id"] != "ctx-1" {
		t.Errorf("payload.contract_id = %v; want ctx-1", pl["contract_id"])
	}
	if pl["caller_agid"] != "agid-x" {
		t.Errorf("payload.caller_agid = %v; want agid-x", pl["caller_agid"])
	}
	if pl["verdict"] != "approved" {
		t.Errorf("payload.verdict = %v; want approved", pl["verdict"])
	}
}

func TestOutboxPublisher_Publish_IdempotencyKeyFromPayload(t *testing.T) {
	t.Parallel()
	store := outbox.NewInMemoryStore()
	pub := outbox.NewPublisher(outbox.PublisherConfig{Store: store, SourceProject: "chora-local"})

	if err := pub.Publish(events.Event{
		Topic: "chora.a2a.partner.registered.v1",
		Payload: map[string]any{
			"idempotency_key": "stable-key",
			"partner_id":      "p1",
		},
		TenantID: "00000000-0000-0000-0000-0000000000aa",
	}); err != nil {
		t.Fatalf("Publish 1: %v", err)
	}
	// A second emit with the same idempotency_key collapses.
	err := pub.Publish(events.Event{
		Topic: "chora.a2a.partner.registered.v1",
		Payload: map[string]any{
			"idempotency_key": "stable-key",
			"partner_id":      "p1",
		},
		TenantID: "00000000-0000-0000-0000-0000000000aa",
	})
	if !errors.Is(err, outbox.ErrDuplicateIdempotencyKey) {
		t.Errorf("Publish 2 err = %v; want ErrDuplicateIdempotencyKey", err)
	}
}

func TestOutboxPublisher_Publish_IdempotencyKeyDefaultsToEventID(t *testing.T) {
	t.Parallel()
	store := outbox.NewInMemoryStore()
	pub := outbox.NewPublisher(outbox.PublisherConfig{Store: store, SourceProject: "chora-local"})
	err := pub.Publish(events.Event{
		Topic:    "chora.a2a.partner.registered.v1",
		Payload:  map[string]any{"partner_id": "p1"},
		TenantID: "00000000-0000-0000-0000-0000000000aa",
	})
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	rows, _ := store.FetchPending(context.Background(), 1)
	if rows[0].IdempotencyKey == "" {
		t.Errorf("IdempotencyKey empty; want UUIDv7 fallback")
	}
	if rows[0].IdempotencyKey != rows[0].ID {
		t.Errorf("IdempotencyKey %q != ID %q; default should equal event_id",
			rows[0].IdempotencyKey, rows[0].ID)
	}
}

func TestOutboxPublisher_Publish_DefaultsSourceProjectAndService(t *testing.T) {
	t.Parallel()
	store := outbox.NewInMemoryStore()
	pub := outbox.NewPublisher(outbox.PublisherConfig{Store: store}) // no project/service
	err := pub.Publish(events.Event{
		Topic:    "chora.a2a.partner.registered.v1",
		Payload:  map[string]any{"partner_id": "p"},
		TenantID: "00000000-0000-0000-0000-0000000000aa",
	})
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	rows, _ := store.FetchPending(context.Background(), 1)
	if rows[0].Envelope["source_project"] != "chora-local" {
		t.Errorf("default source_project = %q; want chora-local", rows[0].Envelope["source_project"])
	}
	if rows[0].Envelope["source_service"] != "chora-a2a-gateway" {
		t.Errorf("default source_service = %q; want chora-a2a-gateway", rows[0].Envelope["source_service"])
	}
}

// The production wiring (cmd/server/main.go) now passes events.SourceProject
// into PublisherConfig. It previously passed nothing, so NewPublisher's own
// chora-local fallback supplied the value on every production event: the
// manifest set CHORA_SOURCE_PROJECT and the overlay rewrote it per
// environment, but no code on this path read it.
//
// This asserts the change is INERT in an estate that does not override the
// variable: the stamped source_project is byte-identical whether the caller
// passes events.SourceProject or leaves the field empty. It is not a claim
// about a second org, where the two legitimately differ, which is the whole
// point of the fix. events.SourceProject is a package var resolved at init,
// so this cannot be exercised with t.Setenv; the wired arm is the real value
// the binary would use with no override present.
func TestOutboxPublisher_WiredSourceProjectMatchesFallback(t *testing.T) {
	t.Parallel()
	ev := events.Event{
		Topic:    "chora.a2a.partner.registered.v1",
		Payload:  map[string]any{"partner_id": "p"},
		TenantID: "00000000-0000-0000-0000-0000000000aa",
	}

	fallbackStore := outbox.NewInMemoryStore()
	if err := outbox.NewPublisher(outbox.PublisherConfig{Store: fallbackStore}).Publish(ev); err != nil {
		t.Fatalf("Publish (fallback arm): %v", err)
	}
	wiredStore := outbox.NewInMemoryStore()
	if err := outbox.NewPublisher(outbox.PublisherConfig{
		Store:         wiredStore,
		SourceProject: events.SourceProject,
	}).Publish(ev); err != nil {
		t.Fatalf("Publish (wired arm): %v", err)
	}

	fallbackRows, _ := fallbackStore.FetchPending(context.Background(), 1)
	wiredRows, _ := wiredStore.FetchPending(context.Background(), 1)
	if len(fallbackRows) != 1 || len(wiredRows) != 1 {
		t.Fatalf("rows = %d fallback, %d wired; want 1 each", len(fallbackRows), len(wiredRows))
	}
	got, want := wiredRows[0].Envelope["source_project"], fallbackRows[0].Envelope["source_project"]
	if got != want {
		t.Errorf("wired source_project = %q; fallback stamped %q: the change is NOT inert in this estate", got, want)
	}
	if want != "chora-local" {
		t.Errorf("fallback arm stamped %q; want chora-local (the control: this test is only meaningful with no CHORA_SOURCE_PROJECT override)", want)
	}
}

func TestOutboxPublisher_Publish_EventTypeDerivedFromTopic(t *testing.T) {
	t.Parallel()
	store := outbox.NewInMemoryStore()
	pub := outbox.NewPublisher(outbox.PublisherConfig{Store: store, SourceProject: "chora-local"})
	tests := []struct {
		topic        string
		wantEvType   string
		wantContains string
	}{
		{"chora.a2a.contract.invoked.v1", "a2a.contract.invoked", "contract"},
		{"chora.a2a.invocation.failed.v1", "a2a.invocation.failed", "invocation"},
		{"chora.a2a.partner.suspended.v1", "a2a.partner.suspended", "partner"},
		{"chora.a2a.agid.registered.v1", "a2a.agid.registered", "agid"},
	}
	for _, tc := range tests {
		_ = pub.Publish(events.Event{
			Topic:    tc.topic,
			TenantID: "00000000-0000-0000-0000-0000000000aa",
			Payload:  map[string]any{"k": "v"},
		})
	}
	rows, _ := store.FetchPending(context.Background(), 10)
	if len(rows) != len(tests) {
		t.Fatalf("rows = %d; want %d", len(rows), len(tests))
	}
	for i, r := range rows {
		// rows return in occurred_at-ascending order; same Now() means stable index.
		if !strings.HasPrefix(r.EventType, "a2a.") {
			t.Errorf("row[%d].EventType = %q; want prefix a2a.", i, r.EventType)
		}
	}
}

func TestOutboxPublisher_Publish_IMDADimensionCanonicalised(t *testing.T) {
	t.Parallel()
	store := outbox.NewInMemoryStore()
	pub := outbox.NewPublisher(outbox.PublisherConfig{Store: store, SourceProject: "chora-local"})
	err := pub.Publish(events.Event{
		Topic:              "chora.a2a.invocation.completed.v1",
		Payload:            map[string]any{"k": "v"},
		TenantID:           "00000000-0000-0000-0000-0000000000aa",
		IMDADimension:      "Accountability", // upper-case input
		IMDALifecycleStage: "Runtime",
	})
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	rows, _ := store.FetchPending(context.Background(), 1)
	if rows[0].Envelope["chora_imda_dimension"] != "accountability" {
		t.Errorf("envelope.chora_imda_dimension = %q; want accountability",
			rows[0].Envelope["chora_imda_dimension"])
	}
	if rows[0].Envelope["imda_lifecycle_stage"] != "runtime" {
		t.Errorf("envelope.imda_lifecycle_stage = %q; want runtime",
			rows[0].Envelope["imda_lifecycle_stage"])
	}
}

// Compile-time check that TransactionalOutboxPublisher satisfies
// the existing events.Publisher interface.
var _ events.Publisher = (*outbox.Publisher)(nil)

func TestPublisher_AGIDFlowsThroughEnvelope(t *testing.T) {
	t.Parallel()
	store := outbox.NewInMemoryStore()
	pub := outbox.NewPublisher(outbox.PublisherConfig{Store: store, SourceProject: "chora-local"})
	err := pub.Publish(events.Event{
		Topic: "chora.a2a.contract.invoked.v1",
		Payload: map[string]any{
			"agid":        "agid-partner-A",
			"contract_id": "ctx-1",
		},
		TenantID: "00000000-0000-0000-0000-0000000000aa",
	})
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	rows, _ := store.FetchPending(context.Background(), 1)
	if rows[0].AGID != "agid-partner-A" {
		t.Errorf("row.AGID = %q; want agid-partner-A", rows[0].AGID)
	}
}
