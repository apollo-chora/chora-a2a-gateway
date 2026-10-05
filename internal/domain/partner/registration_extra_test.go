// Package partner_test — registration_extra_test.go: extra coverage for
// Reinstate, VerifyAPIKey, IsActive, SoftDeleteRegistration on the
// Registration aggregate.
package partner_test

import (
	"testing"

	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/partner"
)

const approverGCIDExtra = "01970000-0000-7000-9000-000000000099"

func mustRegistration(t *testing.T) *partner.Registration {
	t.Helper()
	r, err := partner.NewRegistration(partner.RegistrationParams{
		ID:                 "01970000-0000-7000-a000-000000000111",
		OrgName:            "Acme",
		ContactEmail:       "ops@acme.example",
		Capabilities:       []string{"recommend"},
		RequestedRateLimit: 100,
	})
	if err != nil {
		t.Fatalf("NewRegistration: %v", err)
	}
	return r
}

func TestRegistration_VerifyAPIKey(t *testing.T) {
	t.Parallel()
	r := mustRegistration(t)
	res, err := r.Approve(partner.ApprovalParams{
		ApprovedByGCID: approverGCIDExtra,
		Tier:           partner.TierLow,
	})
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if !r.VerifyAPIKey(res.APIKeyPlaintext) {
		t.Error("VerifyAPIKey rejected the approval-issued plaintext")
	}
	if r.VerifyAPIKey("wrong-key") {
		t.Error("VerifyAPIKey accepted a wrong key")
	}
}

func TestRegistration_VerifyAPIKey_PendingAndDeleted(t *testing.T) {
	t.Parallel()
	r := mustRegistration(t)
	if r.VerifyAPIKey("anything") {
		t.Error("pending registration accepts any key")
	}
	res, _ := r.Approve(partner.ApprovalParams{
		ApprovedByGCID: approverGCIDExtra,
		Tier:           partner.TierLow,
	})
	r.SoftDeleteRegistration()
	if r.VerifyAPIKey(res.APIKeyPlaintext) {
		t.Error("soft-deleted registration accepts plaintext")
	}
}

func TestRegistration_IsActive(t *testing.T) {
	t.Parallel()
	r := mustRegistration(t)
	if r.IsActive() {
		t.Error("pending IsActive=true")
	}
	_, _ = r.Approve(partner.ApprovalParams{
		ApprovedByGCID: approverGCIDExtra,
		Tier:           partner.TierLow,
	})
	if !r.IsActive() {
		t.Error("approved IsActive=false")
	}
	_ = r.SuspendRegistration("policy", approverGCIDExtra)
	if r.IsActive() {
		t.Error("suspended IsActive=true")
	}
	if err := r.ReinstateRegistration(approverGCIDExtra); err != nil {
		t.Fatalf("Reinstate: %v", err)
	}
	if !r.IsActive() {
		t.Error("reinstated IsActive=false")
	}
}

func TestRegistration_Reinstate_RequiresSuspended(t *testing.T) {
	t.Parallel()
	r := mustRegistration(t)
	_, _ = r.Approve(partner.ApprovalParams{ApprovedByGCID: approverGCIDExtra, Tier: partner.TierLow})
	if err := r.ReinstateRegistration(approverGCIDExtra); err == nil {
		t.Error("expected error reinstating an approved registration")
	}
}

func TestRegistration_SoftDelete(t *testing.T) {
	t.Parallel()
	r := mustRegistration(t)
	r.SoftDeleteRegistration()
	if r.DeletedAt == nil {
		t.Error("DeletedAt nil after SoftDelete")
	}
	if r.IsActive() {
		t.Error("soft-deleted IsActive=true")
	}
}

func TestRegistration_NewRegistration_BadEmail(t *testing.T) {
	t.Parallel()
	cases := []string{"", "no-at", "no-dot@example", "@example.com"}
	for _, e := range cases {
		_, err := partner.NewRegistration(partner.RegistrationParams{
			ID:                 "01970000-0000-7000-a000-000000000111",
			OrgName:            "Acme",
			ContactEmail:       e,
			Capabilities:       []string{"recommend"},
			RequestedRateLimit: 1,
		})
		if err == nil {
			t.Errorf("email %q accepted", e)
		}
	}
}
