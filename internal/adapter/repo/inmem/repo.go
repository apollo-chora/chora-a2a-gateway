// Package inmem provides in-memory repository adapters for the
// chora-a2a-gateway external surface. M12 swaps these for Postgres repos
// in the chora_a2a database.
//
// Repos:
//   - RegistrationRepo — partner registrations (state-machine aggregate)
//   - ContractRepo     — A2AContract aggregate (versioned)
//   - InvocationRepo   — A2AInvocation append-only audit log
//   - BYOAKeyRepo      — encrypted BYOA key vault entries
//   - MCPConfigRepo    — per-tenant MCP gateway add-on config
package inmem

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/repo"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/contract"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/invocation"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/mcp"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/partner"
)

// ErrNotFound is an alias for repo.ErrNotFound so callers using the legacy
// inmem.ErrNotFound check stay backwards-compatible after the pg-backend
// swap (M12 backlog).
var ErrNotFound = repo.ErrNotFound

// ErrAlreadyExists is an alias for repo.ErrAlreadyExists with the same
// rationale — the audit log Append rejects duplicate IDs identically
// across both backends.
var ErrAlreadyExists = repo.ErrAlreadyExists

// -----------------------------------------------------------------------------
// RegistrationRepo
// -----------------------------------------------------------------------------

// RegistrationRepo persists partner.Registration aggregates by ID.
type RegistrationRepo struct {
	mu sync.RWMutex
	m  map[string]*partner.Registration
}

func NewRegistrationRepo() *RegistrationRepo {
	return &RegistrationRepo{m: make(map[string]*partner.Registration)}
}

func (r *RegistrationRepo) Put(reg *partner.Registration) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[reg.ID] = reg
	return nil
}

func (r *RegistrationRepo) Get(id string) (*partner.Registration, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	reg, ok := r.m[id]
	if !ok {
		return nil, ErrNotFound
	}
	return reg, nil
}

// GetByAGID returns the (approved) registration whose AGID matches.
// Returns ErrNotFound if no approved registration owns the AGID.
func (r *RegistrationRepo) GetByAGID(agid string) (*partner.Registration, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, reg := range r.m {
		if reg.AGID == agid {
			return reg, nil
		}
	}
	return nil, ErrNotFound
}

// ListByStatus returns all non-deleted registrations in the given state,
// sorted by CreatedAt ascending.
func (r *RegistrationRepo) ListByStatus(state partner.RegistrationState) ([]*partner.Registration, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*partner.Registration, 0)
	for _, reg := range r.m {
		if reg.DeletedAt != nil {
			continue
		}
		if reg.State != state {
			continue
		}
		out = append(out, reg)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

// ListAll returns all non-deleted registrations sorted by CreatedAt ascending.
// Backs the O+ /api/v1/a2a/identities listing endpoint (Phase B7).
func (r *RegistrationRepo) ListAll() ([]*partner.Registration, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*partner.Registration, 0, len(r.m))
	for _, reg := range r.m {
		if reg.DeletedAt != nil {
			continue
		}
		out = append(out, reg)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

// -----------------------------------------------------------------------------
// ContractRepo
// -----------------------------------------------------------------------------

// ContractRepo persists contract.Contract aggregates by ID.
type ContractRepo struct {
	mu sync.RWMutex
	m  map[string]*contract.Contract
}

func NewContractRepo() *ContractRepo {
	return &ContractRepo{m: make(map[string]*contract.Contract)}
}

func (r *ContractRepo) Put(c *contract.Contract) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[c.ID] = c
	return nil
}

func (r *ContractRepo) Get(id string) (*contract.Contract, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.m[id]
	if !ok {
		return nil, ErrNotFound
	}
	return c, nil
}

// ListByPartner returns all non-deleted contracts owned by the partner,
// sorted by CreatedAt ascending.
func (r *ContractRepo) ListByPartner(partnerID string) ([]*contract.Contract, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*contract.Contract, 0)
	for _, c := range r.m {
		if c.DeletedAt != nil {
			continue
		}
		if c.PartnerID == partnerID {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

// ListAll returns all non-deleted contracts sorted by CreatedAt ascending.
// Backs the O+ /api/v1/a2a/contracts listing endpoint (Phase B7).
func (r *ContractRepo) ListAll() ([]*contract.Contract, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*contract.Contract, 0, len(r.m))
	for _, c := range r.m {
		if c.DeletedAt != nil {
			continue
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

// -----------------------------------------------------------------------------
// InvocationRepo (append-only)
// -----------------------------------------------------------------------------

// InvocationRepo persists invocation.Invocation as an append-only audit log.
type InvocationRepo struct {
	mu sync.RWMutex
	m  map[string]*invocation.Invocation
}

func NewInvocationRepo() *InvocationRepo {
	return &InvocationRepo{m: make(map[string]*invocation.Invocation)}
}

// Append inserts a new invocation. Rejects duplicates by ID — the audit
// log is append-only, so a duplicate ID is a programming error.
func (r *InvocationRepo) Append(i *invocation.Invocation) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.m[i.ID]; ok {
		return ErrAlreadyExists
	}
	r.m[i.ID] = i
	return nil
}

// Update is allowed only for the started → terminal transition (the
// existing record is replaced atomically). Schema-level enforcement
// (immutable agid/capability/correlation_id) is mirrored from the
// PostgreSQL trigger in migrations/0001_initial.sql.
func (r *InvocationRepo) Update(i *invocation.Invocation) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	old, ok := r.m[i.ID]
	if !ok {
		return ErrNotFound
	}
	if old.AGID != i.AGID {
		return errors.New("invocation: AGID is immutable")
	}
	if old.Capability != i.Capability {
		return errors.New("invocation: Capability is immutable")
	}
	if old.CorrelationID != i.CorrelationID {
		return errors.New("invocation: CorrelationID is immutable")
	}
	r.m[i.ID] = i
	return nil
}

// Get returns the invocation by ID.
func (r *InvocationRepo) Get(id string) (*invocation.Invocation, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	i, ok := r.m[id]
	if !ok {
		return nil, ErrNotFound
	}
	return i, nil
}

// ListByPartner returns all invocations for a partner, sorted by StartedAt.
func (r *InvocationRepo) ListByPartner(partnerID string) ([]*invocation.Invocation, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*invocation.Invocation, 0)
	for _, i := range r.m {
		if i.PartnerID == partnerID {
			out = append(out, i)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt.Before(out[j].StartedAt) })
	return out, nil
}

// ListSince returns all invocations with StartedAt >= since, sorted by
// StartedAt descending (newest first). A zero `since` returns the full log.
// Backs the O+ /api/v1/a2a/invocations?since=... listing endpoint (Phase B7).
func (r *InvocationRepo) ListSince(since time.Time) ([]*invocation.Invocation, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*invocation.Invocation, 0, len(r.m))
	for _, i := range r.m {
		if !since.IsZero() && i.StartedAt.Before(since) {
			continue
		}
		out = append(out, i)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt.After(out[j].StartedAt) })
	return out, nil
}

// -----------------------------------------------------------------------------
// BYOAKeyRepo
// -----------------------------------------------------------------------------

// BYOAKeyEntry aliases repo.BYOAKeyEntry — the encrypted BYOA external-LLM
// provider-key vault row's canonical wire shape now lives on the port
// (internal/adapter/repo) so this in-memory adapter and the pg adapter
// (internal/adapter/repo/pg/byoakey.go) share ONE shape, exactly like MCPConfig
// above. Kept as a type ALIAS (not a new named type) so every existing call
// site — ext_router.go's BYOA handler, this package's own tests — keeps
// compiling unchanged after the W0-F1 pg-durability swap (CHO-2198).
type BYOAKeyEntry = repo.BYOAKeyEntry

type byoaKeyKey struct{ TenantID, Provider string }

// BYOAKeyRepo persists BYOA encrypted entries by (tenant, provider).
type BYOAKeyRepo struct {
	mu sync.RWMutex
	m  map[byoaKeyKey]*BYOAKeyEntry
}

func NewBYOAKeyRepo() *BYOAKeyRepo {
	return &BYOAKeyRepo{m: make(map[byoaKeyKey]*BYOAKeyEntry)}
}

func (r *BYOAKeyRepo) Put(e *BYOAKeyEntry) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[byoaKeyKey{e.TenantID, e.Provider}] = e
	return nil
}

func (r *BYOAKeyRepo) Get(tenantID, provider string) (*BYOAKeyEntry, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.m[byoaKeyKey{tenantID, provider}]
	if !ok || e.DeletedAt != nil {
		return nil, ErrNotFound
	}
	return e, nil
}

// SoftDelete marks the entry tombstoned (key rotation / revocation).
func (r *BYOAKeyRepo) SoftDelete(tenantID, provider string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.m[byoaKeyKey{tenantID, provider}]
	if !ok {
		return ErrNotFound
	}
	now := time.Now().UTC()
	e.DeletedAt = &now
	return nil
}

// -----------------------------------------------------------------------------
// MCPConfigRepo
// -----------------------------------------------------------------------------

// MCPConfig aliases repo.MCPConfig — the per-tenant MCP gateway add-on
// config's canonical shape now lives on the port (internal/adapter/repo)
// so this in-memory adapter and the pg adapter
// (internal/adapter/repo/pg/mcpconfig.go) share one wire shape. Kept as a
// type ALIAS (not a new named type) so every existing call site —
// ext_router.go's ExtConfig wiring, this package's own tests — keeps
// compiling unchanged.
type MCPConfig = repo.MCPConfig

// MCPConfigRepo persists MCPConfig per tenant.
type MCPConfigRepo struct {
	mu sync.RWMutex
	m  map[string]*MCPConfig
}

func NewMCPConfigRepo() *MCPConfigRepo {
	return &MCPConfigRepo{m: make(map[string]*MCPConfig)}
}

func (r *MCPConfigRepo) Put(c *MCPConfig) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[c.TenantID] = c
	return nil
}

func (r *MCPConfigRepo) Get(tenantID string) (*MCPConfig, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.m[tenantID]
	if !ok || c.DeletedAt != nil {
		return nil, ErrNotFound
	}
	return c, nil
}

// ByAPIKeyHash implements mcp.Store: it reverse-looks-up a LIVE per-tenant
// MCP add-on by the SHA-256 hash of its API key (the key the MCP gateway
// presents to POST /admin/mcp/_resolve), mapping the row into a domain
// mcp.AddOn. Soft-deleted (revoked) add-ons are skipped and a miss returns
// mcp.ErrNotFound — so a revoked key resolves as invalid, never as identity.
//
// The skeleton scans the (small) in-memory set; the M12 pg backend serves this
// from an indexed WHERE api_key_hash = $1 AND deleted_at IS NULL.
func (r *MCPConfigRepo) ByAPIKeyHash(_ context.Context, keyHash string) (mcp.AddOn, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, c := range r.m {
		if c.DeletedAt != nil {
			continue
		}
		if c.APIKeyHash == keyHash {
			return mcp.AddOn{
				TenantID:  c.TenantID,
				Scopes:    append([]string(nil), c.AllowedTools...),
				Suspended: c.Suspended,
			}, nil
		}
	}
	return mcp.AddOn{}, mcp.ErrNotFound
}

// SetSuspended toggles the reversible admin pause on a live (non-revoked)
// MCPConfig — backs /admin/mcp/{tenant_id}:suspend and :reinstate. Returns
// ErrNotFound for an absent OR already-revoked tenant: revocation is
// permanent, so a hard-revoked add-on cannot be resurrected through this
// side door (a fresh POST /admin/mcp/{tenant_id} is required instead).
func (r *MCPConfigRepo) SetSuspended(tenantID string, suspended bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.m[tenantID]
	if !ok || c.DeletedAt != nil {
		return ErrNotFound
	}
	c.Suspended = suspended
	c.UpdatedAt = time.Now().UTC()
	return nil
}
