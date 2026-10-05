// Package partner_test — hash_test.go: the exported HashAPIKey is the single
// canonical credential digest. It MUST be the SHA-256 hex of the plaintext
// (matching what Registration.Approve mints + VerifyAPIKey checks), so the
// MCP add-on resolve path can reuse the SAME hash as the registration verify
// path (CHO-1971) rather than a forgeable AGID-derived placeholder.
package partner_test

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/partner"
)

func TestHashAPIKey_IsSHA256Hex(t *testing.T) {
	t.Parallel()
	const plaintext = "an-opaque-32-byte-hex-api-key"
	sum := sha256.Sum256([]byte(plaintext))
	want := hex.EncodeToString(sum[:])
	if got := partner.HashAPIKey(plaintext); got != want {
		t.Errorf("HashAPIKey = %q; want SHA-256 hex %q", got, want)
	}
}

func TestHashAPIKey_MatchesRegistrationVerifyPath(t *testing.T) {
	t.Parallel()
	reg, err := partner.NewRegistration(partner.RegistrationParams{
		ID:                 "01970000-0000-7000-a000-0000000000f1",
		OrgName:            "Atlas",
		ContactEmail:       "ops@atlas.example",
		Capabilities:       []string{"recommend_content"},
		RequestedRateLimit: 60,
	})
	if err != nil {
		t.Fatalf("NewRegistration: %v", err)
	}
	res, err := reg.Approve(partner.ApprovalParams{
		ApprovedByGCID: "01970000-0000-7000-9000-0000000000aa",
		Tier:           partner.TierMedium,
	})
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	// The hash the registration persists is exactly HashAPIKey(plaintext), and
	// it round-trips through the verify path.
	if reg.APIKeyHash != partner.HashAPIKey(res.APIKeyPlaintext) {
		t.Errorf("APIKeyHash = %q; want HashAPIKey(plaintext)", reg.APIKeyHash)
	}
	if !reg.VerifyAPIKey(res.APIKeyPlaintext) {
		t.Error("VerifyAPIKey(plaintext) = false; the canonical hash must verify the minted key")
	}
}

func TestHashAPIKey_Deterministic(t *testing.T) {
	t.Parallel()
	if partner.HashAPIKey("k") != partner.HashAPIKey("k") {
		t.Error("HashAPIKey is not deterministic")
	}
	if partner.HashAPIKey("a") == partner.HashAPIKey("b") {
		t.Error("HashAPIKey collided on distinct inputs")
	}
}
