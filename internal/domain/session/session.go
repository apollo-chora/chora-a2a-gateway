// Package session implements the A2ASession aggregate — a per-call invocation
// log entry, append-only.
//
// CRITICAL invariants (CLAUDE.md §1, ADR-132):
//   - Session holds AGID, NEVER a GCID. Agents do not have GCIDs.
//   - Append-only: a session is created on /a2a/v1/invoke; once terminated
//     (Complete or Fail) it cannot be mutated. Each invocation creates a
//     NEW session entry; there is no UPDATE.
//
// Note: the user's task spec describes A2ASession as the simpler skeleton
// shape (correlation_id, agid, action, started_at, ended_at, status,
// response_size_bytes). The full A2ATask aggregate per ADR-132 §5 is M12+
// work.
package session

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Status is the session terminal state.
type Status string

const (
	StatusStarted   Status = "started"
	StatusCompleted Status = "completed"
	StatusFailed    Status = "failed"
)

// Session is the aggregate root.
//
// NO Gcid field — AGID is the partner-agent identity. CLAUDE.md §1.
type Session struct {
	CorrelationID     string
	AGID              string
	Action            string
	Status            Status
	StartedAt         time.Time
	EndedAt           *time.Time
	ResponseSizeBytes int
	ErrorCode         string
}

// NewParams is the input shape for New.
type NewParams struct {
	CorrelationID string
	AGID          string
	Action        string
}

// New constructs a fresh Session.
func New(p NewParams) (*Session, error) {
	if strings.TrimSpace(p.CorrelationID) == "" {
		return nil, errors.New("session: CorrelationID required")
	}
	if strings.TrimSpace(p.AGID) == "" {
		return nil, errors.New("session: AGID required")
	}
	if strings.TrimSpace(p.Action) == "" {
		return nil, errors.New("session: Action required")
	}
	return &Session{
		CorrelationID: p.CorrelationID,
		AGID:          p.AGID,
		Action:        p.Action,
		Status:        StatusStarted,
		StartedAt:     time.Now().UTC(),
	}, nil
}

// Complete marks the session as completed with the given response size.
// Append-only: rejects a second termination attempt.
func (s *Session) Complete(responseSizeBytes int) error {
	if s.Status != StatusStarted {
		return fmt.Errorf("session: cannot Complete in status %q (append-only invariant)", s.Status)
	}
	if responseSizeBytes < 0 {
		return errors.New("session: response size must be >= 0")
	}
	now := time.Now().UTC()
	s.Status = StatusCompleted
	s.EndedAt = &now
	s.ResponseSizeBytes = responseSizeBytes
	return nil
}

// Fail marks the session as failed with the given error code.
func (s *Session) Fail(errorCode string) error {
	if s.Status != StatusStarted {
		return fmt.Errorf("session: cannot Fail in status %q (append-only invariant)", s.Status)
	}
	now := time.Now().UTC()
	s.Status = StatusFailed
	s.EndedAt = &now
	s.ErrorCode = errorCode
	return nil
}

// MarshalForAudit returns a plain key=value text representation safe for
// emitting to logs / O+ audit. It deliberately enumerates fields explicitly
// so a contributor adding a Gcid field would have to add it here too —
// the unit test asserts the absence of a "gcid" key.
func MarshalForAudit(s *Session) string {
	end := ""
	if s.EndedAt != nil {
		end = s.EndedAt.Format(time.RFC3339)
	}
	return fmt.Sprintf(
		`{"correlation_id":%q,"agid":%q,"action":%q,"status":%q,"started_at":%q,"ended_at":%q,"response_size_bytes":%d,"error_code":%q}`,
		s.CorrelationID,
		s.AGID,
		s.Action,
		string(s.Status),
		s.StartedAt.Format(time.RFC3339),
		end,
		s.ResponseSizeBytes,
		s.ErrorCode,
	)
}
