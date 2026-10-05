// Package invocation implements the A2AInvocation aggregate per ADR-132 §5.
//
// Every external A2A call writes one Invocation record (append-only audit
// log). The aggregate captures the per-call outcome — capability invoked,
// status, latency, optional error code, optional response size, dispatch
// endpoint.
//
// CRITICAL invariants:
//   - AGID required (CLAUDE.md §1 — invocation log carries AGID, never GCID)
//   - PartnerID required, non-empty (UUIDv7)
//   - Capability required, non-empty
//   - CorrelationID required, non-empty (idempotency anchor + request-id)
//   - Status terminal states: completed | failed | rate_limited | scope_denied
//   - Each terminal transition records EndedAt + LatencyMS (>= 0)
//   - Audit entry MUST NOT carry a "gcid" key
//   - Endpoint is optional but, when present, MUST be the real dispatch URL
//     the gateway routed to. NEVER substitute a placeholder like "unknown".
package invocation

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Status is the invocation lifecycle state.
type Status string

const (
	StatusStarted     Status = "started"
	StatusCompleted   Status = "completed"
	StatusFailed      Status = "failed"
	StatusRateLimited Status = "rate_limited"
	StatusScopeDenied Status = "scope_denied"
)

// Invocation is the aggregate root.
//
// NO Gcid field — audit carries AGID only (CLAUDE.md §1).
type Invocation struct {
	ID                string // UUIDv7
	AGID              string // partner agent identity (NOT GCID)
	PartnerID         string // owning partner registration ID
	Capability        string // requested capability
	CorrelationID     string // append-only idempotency anchor
	Status            Status
	LatencyMS         int
	ResponseSizeBytes int
	ErrorCode         string
	StartedAt         time.Time
	EndedAt           *time.Time
	Traceparent       string
	// Endpoint is the dispatch URL the gateway routed this invocation to
	// (e.g. `https://a2a.chora.site/a2a/invoke#recommend_content` or, when
	// the partner declared a partner_domain at registration, the partner's
	// own capability URL). Empty when no endpoint was resolved (legacy
	// rows / scope-denied before resolution). Callers MUST emit empty —
	// never a placeholder like "unknown" — to preserve the honest-null
	// contract surfaced on the O+ A2A console.
	Endpoint string
}

// NewParams is the input shape for New.
type NewParams struct {
	ID            string
	AGID          string
	PartnerID     string
	Capability    string
	CorrelationID string
	Traceparent   string
	// Endpoint is the dispatch URL the gateway will route this invocation
	// to. Optional — leave empty when the dispatcher does not resolve a
	// target (e.g. scope-denied before routing). NEVER pass a placeholder
	// like "unknown".
	Endpoint string
}

// New constructs a fresh Invocation in the started state.
func New(p NewParams) (*Invocation, error) {
	if strings.TrimSpace(p.ID) == "" {
		return nil, errors.New("invocation: ID required")
	}
	if strings.TrimSpace(p.AGID) == "" {
		return nil, errors.New("invocation: AGID required")
	}
	if strings.TrimSpace(p.PartnerID) == "" {
		return nil, errors.New("invocation: PartnerID required")
	}
	if strings.TrimSpace(p.Capability) == "" {
		return nil, errors.New("invocation: Capability required")
	}
	if strings.TrimSpace(p.CorrelationID) == "" {
		return nil, errors.New("invocation: CorrelationID required")
	}
	return &Invocation{
		ID:            strings.TrimSpace(p.ID),
		AGID:          strings.TrimSpace(p.AGID),
		PartnerID:     strings.TrimSpace(p.PartnerID),
		Capability:    strings.TrimSpace(p.Capability),
		CorrelationID: strings.TrimSpace(p.CorrelationID),
		Status:        StatusStarted,
		StartedAt:     time.Now().UTC(),
		Traceparent:   strings.TrimSpace(p.Traceparent),
		Endpoint:      strings.TrimSpace(p.Endpoint),
	}, nil
}

// Complete transitions started → completed and records the response size.
func (i *Invocation) Complete(responseSizeBytes int) error {
	if err := i.assertStarted("Complete"); err != nil {
		return err
	}
	if responseSizeBytes < 0 {
		return errors.New("invocation: ResponseSizeBytes must be >= 0")
	}
	i.terminate(StatusCompleted)
	i.ResponseSizeBytes = responseSizeBytes
	return nil
}

// Fail transitions started → failed and records the error code.
func (i *Invocation) Fail(errorCode string) error {
	if err := i.assertStarted("Fail"); err != nil {
		return err
	}
	i.terminate(StatusFailed)
	i.ErrorCode = strings.TrimSpace(errorCode)
	return nil
}

// RateLimit transitions started → rate_limited.
func (i *Invocation) RateLimit() error {
	if err := i.assertStarted("RateLimit"); err != nil {
		return err
	}
	i.terminate(StatusRateLimited)
	i.ErrorCode = "RATE_LIMITED"
	return nil
}

// ScopeDeny transitions started → scope_denied with the deny reason.
func (i *Invocation) ScopeDeny(reason string) error {
	if err := i.assertStarted("ScopeDeny"); err != nil {
		return err
	}
	i.terminate(StatusScopeDenied)
	if reason == "" {
		reason = "SCOPE_DENIED"
	}
	i.ErrorCode = strings.ToUpper(strings.TrimSpace(reason))
	return nil
}

// IsTerminal reports whether the invocation is in a non-mutable terminal state.
func (i *Invocation) IsTerminal() bool {
	return i.Status != StatusStarted
}

func (i *Invocation) assertStarted(op string) error {
	if i.Status != StatusStarted {
		return fmt.Errorf("invocation: cannot %s in status %q (terminal append-only)", op, i.Status)
	}
	return nil
}

func (i *Invocation) terminate(s Status) {
	now := time.Now().UTC()
	i.Status = s
	i.EndedAt = &now
	if i.StartedAt.IsZero() {
		i.LatencyMS = 0
		return
	}
	delta := now.Sub(i.StartedAt).Milliseconds()
	if delta < 0 {
		delta = 0
	}
	i.LatencyMS = int(delta)
}

// MarshalAuditEntry returns a deterministic JSON-shaped string for the
// invocation audit log. The format deliberately enumerates fields explicitly;
// a contributor adding a Gcid field would have to add it here as well — the
// unit test asserts the absence of any "gcid" key.
func MarshalAuditEntry(i *Invocation) string {
	end := ""
	if i.EndedAt != nil {
		end = i.EndedAt.Format(time.RFC3339)
	}
	return fmt.Sprintf(
		`{"id":%q,"agid":%q,"partner_id":%q,"capability":%q,"correlation_id":%q,"status":%q,"latency_ms":%d,"response_size_bytes":%d,"error_code":%q,"started_at":%q,"ended_at":%q,"traceparent":%q,"endpoint":%q}`,
		i.ID,
		i.AGID,
		i.PartnerID,
		i.Capability,
		i.CorrelationID,
		string(i.Status),
		i.LatencyMS,
		i.ResponseSizeBytes,
		i.ErrorCode,
		i.StartedAt.Format(time.RFC3339),
		end,
		i.Traceparent,
		i.Endpoint,
	)
}
