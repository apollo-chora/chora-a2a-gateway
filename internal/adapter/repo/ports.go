// Package repo declares the port interfaces that decouple chora-a2a-gateway
// HTTP / gRPC / closure adapters from the concrete repository backend
// (in-memory for skeleton/tests; Postgres via repo/pg for production).
//
// M12 backlog deliverable: the three aggregate repos backing the O+ A2A
// console listings + ExtRouter partner workflow live behind these ports so
// the wiring in cmd/server/main.go can pick `inmem` (default) or `pg`
// based on CHORA_A2A_REPO_BACKEND without churning consumer signatures.
//
// CRITICAL invariants enforced by every implementation:
//
//   - Soft-delete: list queries filter `deleted_at IS NULL` by default
//     (ddd-enforcement #5 + #6).
//   - Append-only InvocationStore — Update is permitted ONLY for the
//     started → terminal transition; DELETE is forbidden (mirrored from
//     the trigger in migrations/0001_initial.sql).
//   - AGID-keyed lookups never touch a `gcid` column (CLAUDE.md §1).
//
// Tenant context: production pg implementations expect callers to wrap a
// transaction with `SET LOCAL chora.tenant_id` before list/get queries;
// the in-memory implementation is tenant-agnostic.
package repo

import (
	"context"
	"errors"
	"time"

	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/agent_identity"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/contract"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/invocation"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/mcp"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/partner"
)

// ErrNotFound is the canonical "row missing" sentinel for the
// chora-a2a-gateway repository ports. Both backends (inmem + pg) return
// errors that `errors.Is(err, repo.ErrNotFound)` matches — callers
// MUST switch to this sentinel so they remain agnostic to the concrete
// backend selected at bootstrap.
var ErrNotFound = errors.New("repo: not found")

// ErrAlreadyExists is the canonical "duplicate insert" sentinel —
// surfaced by InvocationStore.Append on PK collision (append-only audit
// log invariant).
var ErrAlreadyExists = errors.New("repo: already exists")

// RegistrationStore is the persistence port for partner.Registration
// (workflow aggregate — pending → approved → suspended).
type RegistrationStore interface {
	Put(reg *partner.Registration) error
	Get(id string) (*partner.Registration, error)
	GetByAGID(agid string) (*partner.Registration, error)
	ListByStatus(state partner.RegistrationState) ([]*partner.Registration, error)
	ListAll() ([]*partner.Registration, error)
}

// ContractStore is the persistence port for contract.Contract
// (A2AContract aggregate; versioned + soft-deletable).
type ContractStore interface {
	Put(c *contract.Contract) error
	Get(id string) (*contract.Contract, error)
	ListByPartner(partnerID string) ([]*contract.Contract, error)
	ListAll() ([]*contract.Contract, error)
}

// InvocationStore is the persistence port for invocation.Invocation
// (append-only audit log; status terminal-only update; never delete).
type InvocationStore interface {
	Append(i *invocation.Invocation) error
	Update(i *invocation.Invocation) error
	Get(id string) (*invocation.Invocation, error)
	ListByPartner(partnerID string) ([]*invocation.Invocation, error)
	ListSince(since time.Time) ([]*invocation.Invocation, error)
}

// MCPConfig is the per-tenant MCP-as-a-Service add-on configuration (ADR-132
// §10) — the tool allowlist + credential hash minted when a tenant
// subscribes via POST /admin/mcp/{tenant_id}. Canonically defined here
// (rather than internal/domain/mcp, which only declares the resolve-side
// Store/AddOn contract) so both internal/adapter/repo/inmem (which
// type-aliases its exported MCPConfig to this one) and
// internal/adapter/repo/pg share one wire shape without an import cycle —
// internal/adapter/repo/inmem already imports this package for ErrNotFound/
// ErrAlreadyExists, so the dependency only runs one way.
type MCPConfig struct {
	TenantID     string
	APIKeyHash   string
	AllowedTools []string // MCP tool allowlist
	// Suspended is the reversible admin pause (SetSuspended), distinct from
	// DeletedAt's permanent revoke.
	Suspended bool
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time
}

// MCPConfigStore is the persistence port for MCPConfig. It implements
// mcp.Store by construction (ByAPIKeyHash matches that interface's sole
// method), so any MCPConfigStore can be handed directly to mcp.NewResolver.
//
// ByAPIKeyHash is the pre-tenant reverse lookup backing
// POST /admin/mcp/_resolve: it resolves an opaque partner key to the tenant
// that owns it, which necessarily runs BEFORE any tenant context exists —
// so, unlike Put/Get/SetSuspended, it MUST NOT be scoped by a tenant_id
// filter.
type MCPConfigStore interface {
	Put(c *MCPConfig) error
	Get(tenantID string) (*MCPConfig, error)
	ByAPIKeyHash(ctx context.Context, keyHash string) (mcp.AddOn, error)
	SetSuspended(tenantID string, suspended bool) error
}

// BYOAKeyEntry is a Bring-Your-Own-Agent encrypted external-LLM provider-key
// vault row — the AUTH-state key material (partner API-key ciphertext +
// fingerprint) a tenant submits via POST /admin/byoa/{tenant_id}/{provider}.
// Canonically defined on the port (rather than internal/adapter/repo/inmem)
// so both the in-memory adapter (which type-aliases its exported BYOAKeyEntry
// to this one) and the pg adapter (internal/adapter/repo/pg/byoakey.go) share
// one wire shape — mirrors MCPConfig above. Keyed by (tenant_id, provider).
//
// Ciphertext is the AES-GCM `nonce||ciphertext-with-tag` produced by
// internal/domain/byoa.EncryptKey; the plaintext is NEVER persisted or logged.
// KeyFingerprint is the SHA-256 hex of the plaintext (audit anchor only —
// non-reversible). This is DISTINCT from the byoa_configs table (0003), which
// stores the separate BYOAConfig model-config aggregate keyed (tenant, gcid).
type BYOAKeyEntry struct {
	TenantID       string
	Provider       string // "openai" | "anthropic" | "vertex_byok" (free-form)
	Ciphertext     []byte // nonce || ciphertext-with-tag (AES-GCM)
	KeyFingerprint string // SHA-256 hex of the plaintext (audit anchor only)
	RotatedAt      time.Time
	DeletedAt      *time.Time
}

// BYOAKeyStore is the persistence port for BYOAKeyEntry — partner external-LLM
// API-key hashes (AUTH state). W0-F1 (CHO-2198) makes this DURABLE: the pg
// implementation (internal/adapter/repo/pg/byoakey.go) persists to chora_a2a
// so a pod restart/rollout no longer wipes registered BYOA credentials.
//
// Tenant is carried on the entry (Put) or passed per call (Get/SoftDelete) —
// mirroring MCPConfigStore's per-call tenant, NOT a construction-bound tenant,
// because a single store serves every tenant's (tenant, provider) keys.
type BYOAKeyStore interface {
	Put(e *BYOAKeyEntry) error
	Get(tenantID, provider string) (*BYOAKeyEntry, error)
	SoftDelete(tenantID, provider string) error
}

// IdentityStore is the persistence port for the ExternalAgentIdentity
// aggregate — the partner agent's public-key PEM + SHA-256 fingerprint the O+
// A2A console surfaces (ADR-132 §3). W0-F1 (CHO-2198) makes this DURABLE: the
// pg implementation (internal/adapter/repo/pg/identity.go) persists to
// chora_a2a so registered agent public keys survive a pod restart.
//
// AGID-keyed (agent identity, NOT GCID — CLAUDE.md §1). Tenant is bound at
// construction in the pg adapter (mirroring RegistrationStore), so — unlike
// BYOAKeyStore — no tenant flows through the method signatures: the O+ read
// path lists one env-bound tenant's registrations and their identities.
type IdentityStore interface {
	Put(id *agent_identity.ExternalAgentIdentity) error
	Get(agid string) (*agent_identity.ExternalAgentIdentity, error)
}
