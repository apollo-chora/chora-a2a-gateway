// Package agent_identity implements the ExternalAgentIdentity aggregate —
// the public-key + jwks_uri pair used to verify partner agent JWS
// signatures per ADR-132 §3-4.
//
// Like Partner and Session, this aggregate carries an AGID (UUIDv7) and
// MUST NOT carry a GCID — the AGID-vs-GCID invariant from CLAUDE.md §1.
//
// Skeleton scope: stores the public-key PEM and computes a SHA-256
// fingerprint. Real impl (M14) will additionally verify JWS signatures
// over inbound /a2a/v1/invoke calls.
package agent_identity

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Algorithm is the partner agent signing algorithm.
type Algorithm string

const (
	AlgEd25519 Algorithm = "Ed25519"
)

// ExternalAgentIdentity is the aggregate root.
//
// NO Gcid field. AGID is the agent identity per CLAUDE.md §1.
type ExternalAgentIdentity struct {
	AGID           string
	PublicKeyPEM   string
	KeyFingerprint string // hex-encoded SHA-256 of PEM
	JWKSURI        string
	Algorithm      Algorithm
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// NewParams is the input shape for New.
type NewParams struct {
	AGID         string
	PublicKeyPEM string
	JWKSURI      string
	Algorithm    Algorithm
}

// New constructs a fresh ExternalAgentIdentity.
func New(p NewParams) (*ExternalAgentIdentity, error) {
	if strings.TrimSpace(p.AGID) == "" {
		return nil, errors.New("identity: AGID required")
	}
	if strings.TrimSpace(p.PublicKeyPEM) == "" {
		return nil, errors.New("identity: PublicKeyPEM required")
	}
	// Lightweight PEM-block sanity check; full crypto/x509 ParsePKIXPublicKey
	// validation deferred to M14 when JWS verification is wired.
	if !strings.Contains(p.PublicKeyPEM, "-----BEGIN") || !strings.Contains(p.PublicKeyPEM, "-----END") {
		return nil, errors.New("identity: PublicKeyPEM is not a PEM block")
	}
	if p.Algorithm != AlgEd25519 {
		return nil, fmt.Errorf("identity: unsupported algorithm %q (only Ed25519 in skeleton)", p.Algorithm)
	}

	now := time.Now().UTC()
	return &ExternalAgentIdentity{
		AGID:           p.AGID,
		PublicKeyPEM:   p.PublicKeyPEM,
		KeyFingerprint: fingerprint(p.PublicKeyPEM),
		JWKSURI:        p.JWKSURI,
		Algorithm:      p.Algorithm,
		CreatedAt:      now,
		UpdatedAt:      now,
	}, nil
}

// Rotate replaces the public key + recomputes the fingerprint.
func (i *ExternalAgentIdentity) Rotate(newPEM string) error {
	if !strings.Contains(newPEM, "-----BEGIN") || !strings.Contains(newPEM, "-----END") {
		return errors.New("identity: new PublicKeyPEM is not a PEM block")
	}
	i.PublicKeyPEM = newPEM
	i.KeyFingerprint = fingerprint(newPEM)
	i.UpdatedAt = time.Now().UTC()
	return nil
}

// MarshalForAudit returns a plain JSON text for log emission. The
// unit test asserts no "gcid" key is present.
func MarshalForAudit(i *ExternalAgentIdentity) string {
	return fmt.Sprintf(
		`{"agid":%q,"public_key_fingerprint":%q,"jwks_uri":%q,"algorithm":%q,"created_at":%q}`,
		i.AGID,
		i.KeyFingerprint,
		i.JWKSURI,
		string(i.Algorithm),
		i.CreatedAt.Format(time.RFC3339),
	)
}

func fingerprint(pem string) string {
	sum := sha256.Sum256([]byte(pem))
	return hex.EncodeToString(sum[:])
}
