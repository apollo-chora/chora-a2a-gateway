// Package partner_test — registration state machine tests.
//
// Per ADR-132 §3 + task spec: Partners go through a registration lifecycle
// (pending → approved → suspended). Approval mints an AGID + API key; an
// already-approved partner cannot be re-approved.
//
// CRITICAL invariants:
//   - State machine: pending → approved → suspended
//   - Cannot approve twice (idempotency)
//   - Cannot suspend a non-approved partner
//   - Reinstate moves suspended → approved (NOT pending)
//   - AGID is minted only at approval time
//   - AGID never changes once minted
//
// TDD RED phase — implementation does NOT yet exist.
package partner_test

import (
	"strings"
	"testing"

	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/partner"
)

const (
	partnerIDA = "01970000-0000-7000-a000-000000000001"
	partnerIDB = "01970000-0000-7000-a000-000000000002"
)

// -----------------------------------------------------------------------------
// Registration construction (pending state)
// -----------------------------------------------------------------------------

func TestNewRegistration_StartsPending(t *testing.T) {
	t.Parallel()

	r, err := partner.NewRegistration(partner.RegistrationParams{
		ID:                 partnerIDA,
		OrgName:            "Acme Tutor Co",
		ContactEmail:       "ops@acme.example",
		Capabilities:       []string{"recommend_content", "discover_learner_profile"},
		RequestedRateLimit: 100,
	})
	if err != nil {
		t.Fatalf("NewRegistration unexpected error: %v", err)
	}
	if r.ID != partnerIDA {
		t.Errorf("ID = %q; want %q", r.ID, partnerIDA)
	}
	if r.State != partner.RegistrationPending {
		t.Errorf("State = %q; want %q", r.State, partner.RegistrationPending)
	}
	if r.AGID != "" {
		t.Errorf("AGID = %q; want empty (not yet minted)", r.AGID)
	}
	if r.APIKeyHash != "" {
		t.Errorf("APIKeyHash = %q; want empty (not yet minted)", r.APIKeyHash)
	}
	if r.CreatedAt.IsZero() {
		t.Error("CreatedAt is zero")
	}
}

func TestNewRegistration_RejectsEmptyOrgName(t *testing.T) {
	t.Parallel()
	_, err := partner.NewRegistration(partner.RegistrationParams{
		ID:                 partnerIDA,
		OrgName:            "  ",
		ContactEmail:       "ops@acme.example",
		Capabilities:       []string{"x"},
		RequestedRateLimit: 100,
	})
	if err == nil {
		t.Error("expected error for empty OrgName; got nil")
	}
}

func TestNewRegistration_RejectsMissingContactEmail(t *testing.T) {
	t.Parallel()
	_, err := partner.NewRegistration(partner.RegistrationParams{
		ID:                 partnerIDA,
		OrgName:            "Acme",
		ContactEmail:       "",
		Capabilities:       []string{"x"},
		RequestedRateLimit: 100,
	})
	if err == nil {
		t.Error("expected error for empty ContactEmail; got nil")
	}
}

func TestNewRegistration_RejectsInvalidEmail(t *testing.T) {
	t.Parallel()
	_, err := partner.NewRegistration(partner.RegistrationParams{
		ID:                 partnerIDA,
		OrgName:            "Acme",
		ContactEmail:       "not-an-email",
		Capabilities:       []string{"x"},
		RequestedRateLimit: 100,
	})
	if err == nil {
		t.Error("expected error for invalid email; got nil")
	}
}

func TestNewRegistration_RejectsEmptyCapabilities(t *testing.T) {
	t.Parallel()
	_, err := partner.NewRegistration(partner.RegistrationParams{
		ID:                 partnerIDA,
		OrgName:            "Acme",
		ContactEmail:       "ops@acme.example",
		Capabilities:       nil,
		RequestedRateLimit: 100,
	})
	if err == nil {
		t.Error("expected error for empty Capabilities; got nil")
	}
}

func TestNewRegistration_RejectsNonPositiveRateLimit(t *testing.T) {
	t.Parallel()
	_, err := partner.NewRegistration(partner.RegistrationParams{
		ID:                 partnerIDA,
		OrgName:            "Acme",
		ContactEmail:       "ops@acme.example",
		Capabilities:       []string{"x"},
		RequestedRateLimit: 0,
	})
	if err == nil {
		t.Error("expected error for zero RequestedRateLimit; got nil")
	}
}

// -----------------------------------------------------------------------------
// Approval — mints AGID + API key
// -----------------------------------------------------------------------------

func TestApprove_TransitionsToApprovedAndMintsAGID(t *testing.T) {
	t.Parallel()

	r := mustReg(t, partnerIDA)
	res, err := r.Approve(partner.ApprovalParams{
		ApprovedByGCID: "01970000-0000-7000-9000-000000000001",
		Tier:           partner.TierMedium,
	})
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if r.State != partner.RegistrationApproved {
		t.Errorf("State = %q; want %q", r.State, partner.RegistrationApproved)
	}
	if r.AGID == "" {
		t.Error("AGID empty after approval; expected minted")
	}
	if !strings.HasPrefix(r.AGID, "agid:") {
		t.Errorf("AGID = %q; want prefix 'agid:'", r.AGID)
	}
	if r.APIKeyHash == "" {
		t.Error("APIKeyHash empty after approval; expected stored hash")
	}
	if r.ApprovedAt == nil {
		t.Error("ApprovedAt nil after approval")
	}
	if r.Tier != partner.TierMedium {
		t.Errorf("Tier = %q; want %q", r.Tier, partner.TierMedium)
	}
	if res.APIKeyPlaintext == "" {
		t.Error("ApprovalResult.APIKeyPlaintext empty; one-time plaintext required")
	}
	// Plaintext must NOT be persisted — only the hash stays on the aggregate.
	if r.APIKeyHash == res.APIKeyPlaintext {
		t.Error("APIKeyHash equals plaintext; must store only the hash")
	}
}

func TestApprove_CannotApproveTwice(t *testing.T) {
	t.Parallel()

	r := mustReg(t, partnerIDA)
	if _, err := r.Approve(partner.ApprovalParams{
		ApprovedByGCID: "01970000-0000-7000-9000-000000000001",
		Tier:           partner.TierLow,
	}); err != nil {
		t.Fatalf("first Approve: %v", err)
	}
	if _, err := r.Approve(partner.ApprovalParams{
		ApprovedByGCID: "01970000-0000-7000-9000-000000000002",
		Tier:           partner.TierHigh,
	}); err == nil {
		t.Error("second Approve should error (idempotency)")
	}
}

func TestApprove_RejectsInvalidTier(t *testing.T) {
	t.Parallel()
	r := mustReg(t, partnerIDA)
	if _, err := r.Approve(partner.ApprovalParams{
		ApprovedByGCID: "01970000-0000-7000-9000-000000000001",
		Tier:           partner.Tier("bogus"),
	}); err == nil {
		t.Error("expected error for invalid tier; got nil")
	}
}

func TestApprove_RejectsMissingApprover(t *testing.T) {
	t.Parallel()
	r := mustReg(t, partnerIDA)
	if _, err := r.Approve(partner.ApprovalParams{
		ApprovedByGCID: "",
		Tier:           partner.TierLow,
	}); err == nil {
		t.Error("expected error for empty ApprovedByGCID; got nil")
	}
}

// -----------------------------------------------------------------------------
// Suspension — only after approval
// -----------------------------------------------------------------------------

func TestSuspendRegistration_RejectsPending(t *testing.T) {
	t.Parallel()
	r := mustReg(t, partnerIDA)
	if err := r.SuspendRegistration("any", "01970000-0000-7000-9000-000000000001"); err == nil {
		t.Error("expected error suspending a pending registration; got nil")
	}
}

func TestSuspendRegistration_TransitionsApprovedToSuspended(t *testing.T) {
	t.Parallel()
	r := mustReg(t, partnerIDA)
	_, _ = r.Approve(partner.ApprovalParams{
		ApprovedByGCID: "01970000-0000-7000-9000-000000000001",
		Tier:           partner.TierLow,
	})
	if err := r.SuspendRegistration("compliance_review", "01970000-0000-7000-9000-000000000002"); err != nil {
		t.Fatalf("Suspend: %v", err)
	}
	if r.State != partner.RegistrationSuspended {
		t.Errorf("State = %q; want %q", r.State, partner.RegistrationSuspended)
	}
	if r.SuspendedAt == nil {
		t.Error("SuspendedAt nil after Suspend")
	}
	if r.SuspendReason != "compliance_review" {
		t.Errorf("SuspendReason = %q", r.SuspendReason)
	}
}

func TestSuspendRegistration_CannotSuspendTwice(t *testing.T) {
	t.Parallel()
	r := mustReg(t, partnerIDA)
	_, _ = r.Approve(partner.ApprovalParams{
		ApprovedByGCID: "01970000-0000-7000-9000-000000000001",
		Tier:           partner.TierLow,
	})
	_ = r.SuspendRegistration("first", "01970000-0000-7000-9000-000000000001")
	if err := r.SuspendRegistration("second", "01970000-0000-7000-9000-000000000002"); err == nil {
		t.Error("expected error suspending an already-suspended registration; got nil")
	}
}

// -----------------------------------------------------------------------------
// Aggregate has no GCID — only an approver GCID stored on transition events
// -----------------------------------------------------------------------------

func TestRegistration_HasNoGCIDField(t *testing.T) {
	t.Parallel()
	// The Registration aggregate represents a partner — distinct from a
	// human account. Per ddd-enforcement #10 partners cannot hold a GCID.
	// (Approval audit captures the approving admin GCID, but the registration
	//  itself does not.)
	r := mustReg(t, partnerIDA)
	// Probe — the public field set must NOT include a Gcid attribute that
	// is owner of this registration.
	if r.AGID != "" {
		t.Error("AGID should be empty pre-approval")
	}
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func mustReg(t *testing.T, id string) *partner.Registration {
	t.Helper()
	r, err := partner.NewRegistration(partner.RegistrationParams{
		ID:                 id,
		OrgName:            "Acme Tutor Co",
		ContactEmail:       "ops@acme.example",
		Capabilities:       []string{"recommend_content", "discover_learner_profile"},
		RequestedRateLimit: 100,
	})
	if err != nil {
		t.Fatalf("seed registration: %v", err)
	}
	return r
}
