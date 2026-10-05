// Package partner_test — AGID minter tests.
//
// Per task spec: AGID format `agid:{partner_id}:{capability}:{instance}`.
// AGID minter is deterministic for the same input (idempotent) but a
// fresh instance index always produces a fresh AGID.
//
// CRITICAL invariants:
//   - Format prefix `agid:`
//   - Same (partner_id, capability, instance) → same AGID (deterministic)
//   - Different inputs → different AGIDs
//   - Empty inputs rejected
//   - AGID is opaque from the minter's perspective; partner_id stays as the
//     supplied UUIDv7 string.
//
// TDD RED phase — implementation does NOT yet exist.
package partner_test

import (
	"strings"
	"testing"

	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/partner"
)

func TestMintAGID_FormatsCorrectly(t *testing.T) {
	t.Parallel()
	pID := "01970000-0000-7000-a000-000000000001"
	a, err := partner.MintAGID(pID, "recommend_content", "01")
	if err != nil {
		t.Fatalf("MintAGID: %v", err)
	}
	want := "agid:" + pID + ":recommend_content:01"
	if a != want {
		t.Errorf("MintAGID = %q; want %q", a, want)
	}
}

func TestMintAGID_Deterministic(t *testing.T) {
	t.Parallel()
	pID := "01970000-0000-7000-a000-000000000001"
	a1, _ := partner.MintAGID(pID, "discover", "01")
	a2, _ := partner.MintAGID(pID, "discover", "01")
	if a1 != a2 {
		t.Errorf("MintAGID not deterministic: %q vs %q", a1, a2)
	}
}

func TestMintAGID_InstanceFreshness(t *testing.T) {
	t.Parallel()
	pID := "01970000-0000-7000-a000-000000000001"
	a1, _ := partner.MintAGID(pID, "discover", "01")
	a2, _ := partner.MintAGID(pID, "discover", "02")
	if a1 == a2 {
		t.Error("different instances produced identical AGIDs")
	}
}

func TestMintAGID_HasPrefix(t *testing.T) {
	t.Parallel()
	a, _ := partner.MintAGID("01970000-0000-7000-a000-000000000001", "x", "01")
	if !strings.HasPrefix(a, "agid:") {
		t.Errorf("AGID = %q; want prefix 'agid:'", a)
	}
}

func TestMintAGID_RejectsEmptyPartnerID(t *testing.T) {
	t.Parallel()
	_, err := partner.MintAGID("", "x", "01")
	if err == nil {
		t.Error("expected error for empty partnerID; got nil")
	}
}

func TestMintAGID_RejectsEmptyCapability(t *testing.T) {
	t.Parallel()
	_, err := partner.MintAGID("01970000-0000-7000-a000-000000000001", "", "01")
	if err == nil {
		t.Error("expected error for empty capability; got nil")
	}
}

func TestMintAGID_RejectsEmptyInstance(t *testing.T) {
	t.Parallel()
	_, err := partner.MintAGID("01970000-0000-7000-a000-000000000001", "x", "")
	if err == nil {
		t.Error("expected error for empty instance; got nil")
	}
}
