// Package partner — Registration aggregate (partner registration workflow).
//
// Per ADR-132 §3 + task spec: external partners submit a registration
// request (org_name, contact_email, capabilities, requested_rate_limit).
// platform_ops review approves or rejects. Approval mints the partner's
// AGID + a one-time API key (only the bcrypt-style hash is persisted).
//
// State machine:
//
//	pending  → approved (Approve)
//	approved → suspended (SuspendRegistration)
//	suspended → approved (ReinstateRegistration)
//
// Approval is non-idempotent: a second Approve call is rejected so any
// admin tooling that retries does not silently re-mint AGIDs / API keys.
//
// CRITICAL invariants:
//   - Registration aggregate carries NO Gcid field (partner != human).
//     Approver GCID is captured on the approval transition only — for
//     audit — and is not stored on the aggregate root.
//   - AGID + APIKeyHash are minted atomically on Approve.
//   - Soft-delete is preserved via DeletedAt.
package partner

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// RegistrationState is the lifecycle state for a Registration aggregate.
type RegistrationState string

const (
	RegistrationPending   RegistrationState = "pending"
	RegistrationApproved  RegistrationState = "approved"
	RegistrationSuspended RegistrationState = "suspended"
)

// Tier is the per-partner trust tier driving default rate limits.
type Tier string

const (
	TierLow      Tier = "low"
	TierMedium   Tier = "medium"
	TierHigh     Tier = "high"
	TierCritical Tier = "critical"
)

// validTier reports whether t is a recognised tier.
func validTier(t Tier) bool {
	switch t {
	case TierLow, TierMedium, TierHigh, TierCritical:
		return true
	}
	return false
}

// Registration is the aggregate root tracking a partner registration request.
//
// NOTE: there is intentionally NO Gcid field on this aggregate (CLAUDE.md §1).
// The approver's GCID is recorded on transitions for audit only.
type Registration struct {
	ID                 string // UUIDv7
	OrgName            string
	ContactEmail       string
	Capabilities       []string
	RequestedRateLimit int

	State RegistrationState
	Tier  Tier

	// Filled at approval time.
	AGID       string
	APIKeyHash string

	ApprovedByGCID string // captured for audit
	ApprovedAt     *time.Time

	SuspendedByGCID string
	SuspendedAt     *time.Time
	SuspendReason   string

	// DNS-TXT verification (per ADR-132 §8 partner onboarding flow).
	// Set when the registrant declared a partner domain at /partners/register
	// and confirmed via /admin/dns/verify. AGID issuance is gated on
	// DNSVerified for production; the skeleton allows approval without DNS
	// verification (the contract layer is the policy enforcement point).
	PartnerDomain  string
	DNSVerifyToken string
	DNSVerified    bool
	DNSVerifiedAt  *time.Time

	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time
}

// RegistrationParams is the input shape for NewRegistration.
type RegistrationParams struct {
	ID                 string
	OrgName            string
	ContactEmail       string
	Capabilities       []string
	RequestedRateLimit int
}

// NewRegistration constructs a fresh pending Registration. Caller owns the
// ID (UUIDv7).
func NewRegistration(p RegistrationParams) (*Registration, error) {
	if strings.TrimSpace(p.ID) == "" {
		return nil, errors.New("partner: NewRegistration ID required")
	}
	if strings.TrimSpace(p.OrgName) == "" {
		return nil, errors.New("partner: NewRegistration OrgName required")
	}
	if !validEmail(p.ContactEmail) {
		return nil, errors.New("partner: NewRegistration ContactEmail invalid")
	}
	if len(p.Capabilities) == 0 {
		return nil, errors.New("partner: NewRegistration Capabilities required (>=1)")
	}
	if p.RequestedRateLimit <= 0 {
		return nil, fmt.Errorf("partner: NewRegistration RequestedRateLimit must be > 0, got %d", p.RequestedRateLimit)
	}

	caps := make([]string, len(p.Capabilities))
	copy(caps, p.Capabilities)

	now := time.Now().UTC()
	return &Registration{
		ID:                 strings.TrimSpace(p.ID),
		OrgName:            strings.TrimSpace(p.OrgName),
		ContactEmail:       strings.TrimSpace(p.ContactEmail),
		Capabilities:       caps,
		RequestedRateLimit: p.RequestedRateLimit,
		State:              RegistrationPending,
		CreatedAt:          now,
		UpdatedAt:          now,
	}, nil
}

// ApprovalParams captures the inputs required for an admin approval.
type ApprovalParams struct {
	ApprovedByGCID string
	Tier           Tier
}

// ApprovalResult is the side-channel result of an approval. The plaintext
// API key is returned ONCE — callers MUST NOT persist it after returning
// to the partner; only the hash on the aggregate stays on the wire.
type ApprovalResult struct {
	AGID            string
	APIKeyPlaintext string
}

// Approve transitions a pending registration to approved, mints the AGID
// (deterministically from ID + first capability + instance "01") and
// generates a fresh API key. The plaintext API key is returned ONCE in
// ApprovalResult; only the hash is stored on the aggregate.
func (r *Registration) Approve(p ApprovalParams) (ApprovalResult, error) {
	if r.State != RegistrationPending {
		return ApprovalResult{}, fmt.Errorf("partner: cannot Approve in state %q", r.State)
	}
	if strings.TrimSpace(p.ApprovedByGCID) == "" {
		return ApprovalResult{}, errors.New("partner: Approve ApprovedByGCID required")
	}
	if !validTier(p.Tier) {
		return ApprovalResult{}, fmt.Errorf("partner: Approve invalid tier %q", p.Tier)
	}

	// Mint AGID from the FIRST registered capability and a fixed instance
	// "01" — the registration covers a single partner; per-capability
	// AGIDs may be derived later via MintAGID with different instances.
	primary := r.Capabilities[0]
	agid, err := MintAGID(r.ID, primary, "01")
	if err != nil {
		return ApprovalResult{}, fmt.Errorf("partner: Approve MintAGID: %w", err)
	}

	// Generate API key (32 bytes hex == 64 chars).
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return ApprovalResult{}, fmt.Errorf("partner: Approve random: %w", err)
	}
	plaintext := hex.EncodeToString(keyBytes)
	hash := HashAPIKey(plaintext)

	now := time.Now().UTC()
	r.State = RegistrationApproved
	r.Tier = p.Tier
	r.AGID = agid
	r.APIKeyHash = hash
	r.ApprovedByGCID = p.ApprovedByGCID
	r.ApprovedAt = &now
	r.UpdatedAt = now

	return ApprovalResult{
		AGID:            agid,
		APIKeyPlaintext: plaintext,
	}, nil
}

// SuspendRegistration transitions an approved registration to suspended.
// Pending registrations cannot be suspended; reject must be a separate
// transition (M12+).
func (r *Registration) SuspendRegistration(reason, byGCID string) error {
	if r.State != RegistrationApproved {
		return fmt.Errorf("partner: cannot Suspend in state %q (must be approved)", r.State)
	}
	now := time.Now().UTC()
	r.State = RegistrationSuspended
	r.SuspendReason = strings.TrimSpace(reason)
	r.SuspendedByGCID = strings.TrimSpace(byGCID)
	r.SuspendedAt = &now
	r.UpdatedAt = now
	return nil
}

// ReinstateRegistration transitions a suspended registration back to approved.
// Audit logs MUST capture the actor; passed in via byGCID.
func (r *Registration) ReinstateRegistration(byGCID string) error {
	if r.State != RegistrationSuspended {
		return fmt.Errorf("partner: cannot Reinstate in state %q", r.State)
	}
	r.State = RegistrationApproved
	r.SuspendedAt = nil
	r.SuspendReason = ""
	r.SuspendedByGCID = ""
	r.UpdatedAt = time.Now().UTC()
	_ = byGCID // recorded by caller in events; not persisted post-reinstate
	return nil
}

// VerifyAPIKey returns true if plaintext hashes to the stored APIKeyHash.
// Returns false for soft-deleted, non-approved, or non-matching keys.
func (r *Registration) VerifyAPIKey(plaintext string) bool {
	if r.DeletedAt != nil {
		return false
	}
	if r.State != RegistrationApproved {
		return false
	}
	if r.APIKeyHash == "" {
		return false
	}
	return HashAPIKey(plaintext) == r.APIKeyHash
}

// IsActive reports whether the registration is in a state that permits
// invocations.
func (r *Registration) IsActive() bool {
	return r.State == RegistrationApproved && r.DeletedAt == nil
}

// SoftDeleteRegistration sets DeletedAt for soft-delete (ddd-enforcement #5).
func (r *Registration) SoftDeleteRegistration() {
	now := time.Now().UTC()
	r.DeletedAt = &now
	r.UpdatedAt = now
}

// validEmail performs a minimal local-part@domain check. Full RFC validation
// is deferred — this guard rejects the obvious typos in skeleton tests.
func validEmail(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	at := strings.IndexByte(s, '@')
	if at <= 0 || at == len(s)-1 {
		return false
	}
	if strings.IndexByte(s[at+1:], '.') < 0 {
		return false
	}
	return true
}

// HashAPIKey returns the SHA-256 hex digest of the plaintext key. It is the
// single canonical credential digest for the A2A gateway: the registration
// verify path (Approve mints it, VerifyAPIKey checks it) and the MCP-as-a-
// Service add-on resolve path (POST /admin/mcp/_resolve, internal/domain/mcp)
// MUST both route through this function so a key's stored hash and its lookup
// hash can never drift — and so neither path can reintroduce a forgeable
// AGID-derived placeholder (CHO-1971).
//
// SHA-256 is not a password hash — production should use bcrypt/argon2id —
// but this is acceptable for the M11 skeleton because API keys are 32-byte
// random hex strings (256 bits of entropy) where rainbow attacks are
// infeasible. M12 swaps this for argon2id when secrets land in Postgres.
func HashAPIKey(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}
