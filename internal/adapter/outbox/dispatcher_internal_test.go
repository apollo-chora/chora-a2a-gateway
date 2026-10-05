// dispatcher_internal_test.go — direct unit tests for the package-private
// Dispatcher helpers (parseTime + reconstructEnvelope) that the external
// dispatcher_test.go drives only indirectly.
package outbox

import (
	"testing"
	"time"
)

func TestParseTime(t *testing.T) {
	fallback := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)

	// Empty string → fallback.
	if got := parseTime("", fallback); !got.Equal(fallback) {
		t.Errorf("parseTime(\"\") = %v; want fallback", got)
	}
	// RFC3339Nano parses.
	nanos := "2026-05-01T12:34:56.123456789Z"
	if got := parseTime(nanos, fallback); got != time.Date(2026, 5, 1, 12, 34, 56, 123456789, time.UTC) {
		t.Errorf("parseTime(nano) = %v", got)
	}
	// RFC3339 (no nanos) parses via the second layout.
	rfc := "2026-05-01T12:34:56Z"
	if got := parseTime(rfc, fallback); got != time.Date(2026, 5, 1, 12, 34, 56, 0, time.UTC) {
		t.Errorf("parseTime(rfc3339) = %v", got)
	}
	// Garbage → fallback.
	if got := parseTime("not-a-time", fallback); !got.Equal(fallback) {
		t.Errorf("parseTime(garbage) = %v; want fallback", got)
	}
}

func TestReconstructEnvelope_SchemaVersionBranches(t *testing.T) {
	occurred := time.Date(2026, 5, 1, 1, 0, 0, 0, time.UTC)
	row := &Row{
		ID: "row-1", TenantID: "tenant-1", AGID: "agid:1", IdempotencyKey: "ik",
		OccurredAt: occurred,
		Envelope: map[string]string{
			"occurred_at":     "2026-05-01T01:00:00Z",
			"event_id":        "evt-1",
			"idempotency_key": "ik2",
			"tenant_id":       "tenant-2",
			"agid":            "agid:from-env",
		},
	}

	// schema_version valid.
	row.Envelope["schema_version"] = "3"
	env := reconstructEnvelope(row)
	if env.SchemaVersion != 3 {
		t.Errorf("SchemaVersion = %d; want 3", env.SchemaVersion)
	}
	if env.EventID != "evt-1" || env.IdempotencyKey != "ik2" || env.TenantID != "tenant-2" {
		t.Errorf("envelope carried over from map: %+v", env)
	}
	if !env.OccurredAt.Equal(time.Date(2026, 5, 1, 1, 0, 0, 0, time.UTC)) {
		t.Errorf("OccurredAt = %v", env.OccurredAt)
	}

	// invalid schema_version → 1 (parse failure).
	row.Envelope["schema_version"] = "abc"
	if env := reconstructEnvelope(row); env.SchemaVersion != 1 {
		t.Errorf("invalid schema_version = %d; want 1", env.SchemaVersion)
	}
	// non-positive schema_version → 1.
	row.Envelope["schema_version"] = "-5"
	if env := reconstructEnvelope(row); env.SchemaVersion != 1 {
		t.Errorf("negative schema_version = %d; want 1", env.SchemaVersion)
	}
	// missing schema_version → 1.
	delete(row.Envelope, "schema_version")
	if env := reconstructEnvelope(row); env.SchemaVersion != 1 {
		t.Errorf("missing schema_version = %d; want 1", env.SchemaVersion)
	}
}

func TestReconstructEnvelope_FallsBackToRowFields(t *testing.T) {
	occurred := time.Date(2026, 5, 1, 1, 0, 0, 0, time.UTC)
	row := &Row{
		ID: "row-1", TenantID: "tenant-1", AGID: "agid:1", IdempotencyKey: "ik",
		OccurredAt: occurred,
		Envelope:   map[string]string{"occurred_at": "not-a-time"},
	}
	env := reconstructEnvelope(row)
	// Empty map values fall back to the row's flat columns.
	if env.EventID != "row-1" || env.IdempotencyKey != "ik" || env.TenantID != "tenant-1" {
		t.Errorf("fallback fields not applied: %+v", env)
	}
	// occurred_at garbage et al → row.OccurredAt / now.
	if !env.OccurredAt.Equal(occurred) {
		t.Errorf("OccurredAt = %v; want row fallback %v", env.OccurredAt, occurred)
	}
	if env.PublishedAt.IsZero() {
		t.Error("PublishedAt must default to now, never zero")
	}
}
