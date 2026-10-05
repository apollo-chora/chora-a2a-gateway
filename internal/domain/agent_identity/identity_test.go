// Package agent_identity_test exercises the ExternalAgentIdentity aggregate
// per ADR-132 §3-4 (public-key + jwks_uri for partner agent auth).
//
// TDD RED phase — implementation does NOT yet exist.
package agent_identity_test

import (
	"strings"
	"testing"

	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/agent_identity"
)

const (
	agidA   = "01970000-0000-7000-b000-000000000001"
	jwksURI = "https://acme.example.com/.well-known/jwks.json"
	pubPEM  = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n-----END PUBLIC KEY-----"
)

func TestNew_AssignsAGIDPubKeyJWKS(t *testing.T) {
	t.Parallel()

	id, err := agent_identity.New(agent_identity.NewParams{
		AGID:         agidA,
		PublicKeyPEM: pubPEM,
		JWKSURI:      jwksURI,
		Algorithm:    agent_identity.AlgEd25519,
	})
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}
	if id.AGID != agidA {
		t.Errorf("AGID = %q; want %q", id.AGID, agidA)
	}
	if id.PublicKeyPEM != pubPEM {
		t.Errorf("PublicKeyPEM mismatch")
	}
	if id.JWKSURI != jwksURI {
		t.Errorf("JWKSURI mismatch")
	}
	if id.Algorithm != agent_identity.AlgEd25519 {
		t.Errorf("Algorithm = %q; want %q", id.Algorithm, agent_identity.AlgEd25519)
	}
	if id.KeyFingerprint == "" {
		t.Error("KeyFingerprint empty; want SHA-256 of public key")
	}
	if len(id.KeyFingerprint) != 64 {
		t.Errorf("KeyFingerprint length = %d; want 64 hex chars", len(id.KeyFingerprint))
	}
	if id.CreatedAt.IsZero() {
		t.Error("CreatedAt zero; want set")
	}
}

func TestNew_RejectsEmptyAGID(t *testing.T) {
	t.Parallel()
	_, err := agent_identity.New(agent_identity.NewParams{
		AGID:         "",
		PublicKeyPEM: pubPEM,
		Algorithm:    agent_identity.AlgEd25519,
	})
	if err == nil {
		t.Error("expected error for empty AGID; got nil")
	}
}

func TestNew_RejectsMissingPublicKey(t *testing.T) {
	t.Parallel()
	_, err := agent_identity.New(agent_identity.NewParams{
		AGID:         agidA,
		PublicKeyPEM: "",
		Algorithm:    agent_identity.AlgEd25519,
	})
	if err == nil {
		t.Error("expected error for missing public key; got nil")
	}
}

func TestNew_RejectsInvalidPEM(t *testing.T) {
	t.Parallel()
	_, err := agent_identity.New(agent_identity.NewParams{
		AGID:         agidA,
		PublicKeyPEM: "not a pem block",
		Algorithm:    agent_identity.AlgEd25519,
	})
	if err == nil {
		t.Error("expected error for invalid PEM; got nil")
	}
}

func TestNew_RejectsUnsupportedAlgorithm(t *testing.T) {
	t.Parallel()
	_, err := agent_identity.New(agent_identity.NewParams{
		AGID:         agidA,
		PublicKeyPEM: pubPEM,
		Algorithm:    "RSA-PKCS1",
	})
	if err == nil {
		t.Error("expected error for unsupported algorithm; got nil")
	}
}

func TestKeyFingerprint_IsHex(t *testing.T) {
	t.Parallel()
	id, _ := agent_identity.New(agent_identity.NewParams{
		AGID:         agidA,
		PublicKeyPEM: pubPEM,
		Algorithm:    agent_identity.AlgEd25519,
	})
	for _, c := range id.KeyFingerprint {
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
		if !isHex {
			t.Errorf("KeyFingerprint contains non-hex char %q", c)
			break
		}
	}
}

// CRITICAL invariant: identity holds AGID never GCID.
func TestExternalAgentIdentity_HasNoGCIDField(t *testing.T) {
	t.Parallel()
	id, _ := agent_identity.New(agent_identity.NewParams{
		AGID:         agidA,
		PublicKeyPEM: pubPEM,
		Algorithm:    agent_identity.AlgEd25519,
	})
	json := agent_identity.MarshalForAudit(id)
	if strings.Contains(strings.ToLower(json), "\"gcid\"") {
		t.Errorf("identity audit JSON contains gcid; AGID-vs-GCID invariant violated. JSON=%q", json)
	}
}

func TestRotate_UpdatesPublicKeyAndFingerprint(t *testing.T) {
	t.Parallel()
	id, _ := agent_identity.New(agent_identity.NewParams{
		AGID:         agidA,
		PublicKeyPEM: pubPEM,
		Algorithm:    agent_identity.AlgEd25519,
	})
	old := id.KeyFingerprint
	newPEM := "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy=\n-----END PUBLIC KEY-----"
	if err := id.Rotate(newPEM); err != nil {
		t.Fatalf("Rotate unexpected error: %v", err)
	}
	if id.PublicKeyPEM != newPEM {
		t.Error("public key not updated")
	}
	if id.KeyFingerprint == old {
		t.Error("fingerprint did not change after rotate")
	}
}
