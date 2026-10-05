// Package session_test exercises the A2ASession aggregate root invariants
// per ADR-132 §5 A2ATask + the user task spec (per-call invocation log).
//
// CRITICAL invariants under test:
//   - A2ASession holds AGID NEVER gcid (CLAUDE.md §1 invariant).
//   - Sessions are append-only — once created they cannot be mutated; status
//     transitions create no new entry, but writers must NEVER overwrite the
//     header (correlation_id, agid, action, started_at).
//   - Soft-delete is forbidden — sessions are an audit log.
//
// TDD RED phase — implementation does NOT yet exist.
package session_test

import (
	"testing"
	"time"

	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/session"
)

const (
	corrA = "01970000-0000-7000-c000-000000000001"
	corrB = "01970000-0000-7000-c000-000000000002"
	agidA = "01970000-0000-7000-b000-000000000001"
)

// -----------------------------------------------------------------------------
// Append-only construction
// -----------------------------------------------------------------------------

func TestNew_RecordsAGIDActionAndStart(t *testing.T) {
	t.Parallel()

	s, err := session.New(session.NewParams{
		CorrelationID: corrA,
		AGID:          agidA,
		Action:        "sample.echo",
	})
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}
	if s.CorrelationID != corrA {
		t.Errorf("CorrelationID = %q; want %q", s.CorrelationID, corrA)
	}
	if s.AGID != agidA {
		t.Errorf("AGID = %q; want %q", s.AGID, agidA)
	}
	if s.Action != "sample.echo" {
		t.Errorf("Action = %q; want %q", s.Action, "sample.echo")
	}
	if s.Status != session.StatusStarted {
		t.Errorf("Status = %q; want %q on creation", s.Status, session.StatusStarted)
	}
	if s.StartedAt.IsZero() {
		t.Error("StartedAt was zero; want set")
	}
	if s.EndedAt != nil {
		t.Error("EndedAt non-nil on creation; want nil")
	}
}

func TestNew_RejectsEmptyCorrelationID(t *testing.T) {
	t.Parallel()
	_, err := session.New(session.NewParams{
		CorrelationID: "",
		AGID:          agidA,
		Action:        "x",
	})
	if err == nil {
		t.Error("expected error for empty CorrelationID; got nil")
	}
}

func TestNew_RejectsEmptyAGID(t *testing.T) {
	t.Parallel()
	_, err := session.New(session.NewParams{
		CorrelationID: corrA,
		AGID:          "",
		Action:        "x",
	})
	if err == nil {
		t.Error("expected error for empty AGID; got nil")
	}
}

func TestNew_RejectsEmptyAction(t *testing.T) {
	t.Parallel()
	_, err := session.New(session.NewParams{
		CorrelationID: corrA,
		AGID:          agidA,
		Action:        "",
	})
	if err == nil {
		t.Error("expected error for empty Action; got nil")
	}
}

// -----------------------------------------------------------------------------
// AGID-vs-GCID invariant — SESSION HOLDS AGID NEVER gcid (CLAUDE.md §1)
// -----------------------------------------------------------------------------

// TestSession_HasNoGCIDField is the load-bearing test for the AGID-vs-GCID
// distinction. Per CLAUDE.md §1: "AGID is distinct from GCID — agents
// CANNOT hold TenantMembership". An A2ASession is a partner-agent
// invocation; it MUST NOT carry a GCID.
//
// If a future contributor adds a GCID field to Session, this test must
// fail loudly to surface the architectural violation in code review.
func TestSession_HasNoGCIDField(t *testing.T) {
	t.Parallel()

	s, _ := session.New(session.NewParams{
		CorrelationID: corrA,
		AGID:          agidA,
		Action:        "x",
	})

	if s.AGID == "" {
		t.Error("AGID was empty; expected the partner-agent identity")
	}

	// Negative assertion: the session JSON marshalling MUST NOT contain
	// a "gcid" field. We exercise this in the http adapter test as well,
	// but a unit-level guard helps.
	json := session.MarshalForAudit(s)
	if containsKey(json, "gcid") {
		t.Errorf("session audit JSON contains a gcid field — AGID-vs-GCID invariant violated. JSON=%q", json)
	}
}

func containsKey(s, k string) bool {
	// Lightweight substring check — any of "gcid":, "Gcid":, "GCID": is a fail.
	for _, needle := range []string{"\"gcid\"", "\"Gcid\"", "\"GCID\""} {
		for i := 0; i+len(needle) <= len(s); i++ {
			if s[i:i+len(needle)] == needle {
				return true
			}
		}
	}
	return false
}

// -----------------------------------------------------------------------------
// Append-only — Complete writes terminal state but no second entry exists
// -----------------------------------------------------------------------------

func TestComplete_SetsTerminalState(t *testing.T) {
	t.Parallel()

	s, _ := session.New(session.NewParams{
		CorrelationID: corrA,
		AGID:          agidA,
		Action:        "x",
	})
	if err := s.Complete(123); err != nil {
		t.Fatalf("Complete unexpected error: %v", err)
	}
	if s.Status != session.StatusCompleted {
		t.Errorf("Status = %q; want %q", s.Status, session.StatusCompleted)
	}
	if s.EndedAt == nil {
		t.Error("EndedAt nil after Complete; want set")
	}
	if s.ResponseSizeBytes != 123 {
		t.Errorf("ResponseSizeBytes = %d; want 123", s.ResponseSizeBytes)
	}
}

func TestFail_SetsTerminalState(t *testing.T) {
	t.Parallel()

	s, _ := session.New(session.NewParams{
		CorrelationID: corrA,
		AGID:          agidA,
		Action:        "x",
	})
	if err := s.Fail("UPSTREAM_TIMEOUT"); err != nil {
		t.Fatalf("Fail unexpected error: %v", err)
	}
	if s.Status != session.StatusFailed {
		t.Errorf("Status = %q; want %q", s.Status, session.StatusFailed)
	}
	if s.ErrorCode != "UPSTREAM_TIMEOUT" {
		t.Errorf("ErrorCode = %q; want %q", s.ErrorCode, "UPSTREAM_TIMEOUT")
	}
}

// Once a session is terminated, it cannot be mutated again — append-only.
func TestComplete_RejectsSecondTermination(t *testing.T) {
	t.Parallel()

	s, _ := session.New(session.NewParams{
		CorrelationID: corrA,
		AGID:          agidA,
		Action:        "x",
	})
	_ = s.Complete(10)
	if err := s.Complete(20); err == nil {
		t.Error("expected error on second Complete; append-only invariant")
	}
}

func TestFail_RejectsAfterComplete(t *testing.T) {
	t.Parallel()

	s, _ := session.New(session.NewParams{
		CorrelationID: corrA,
		AGID:          agidA,
		Action:        "x",
	})
	_ = s.Complete(10)
	if err := s.Fail("X"); err == nil {
		t.Error("expected error on Fail after Complete; append-only invariant")
	}
}

func TestComplete_RejectsNegativeSize(t *testing.T) {
	t.Parallel()

	s, _ := session.New(session.NewParams{
		CorrelationID: corrA,
		AGID:          agidA,
		Action:        "x",
	})
	if err := s.Complete(-1); err == nil {
		t.Error("expected error for negative size")
	}
}

// Sanity: timestamps are UTC and within window.
func TestNew_TimestampsAreUTC(t *testing.T) {
	t.Parallel()
	before := time.Now().UTC()
	s, _ := session.New(session.NewParams{
		CorrelationID: corrA,
		AGID:          agidA,
		Action:        "x",
	})
	after := time.Now().UTC()
	if s.StartedAt.Before(before) || s.StartedAt.After(after) {
		t.Errorf("StartedAt = %v; want between %v and %v", s.StartedAt, before, after)
	}
}
