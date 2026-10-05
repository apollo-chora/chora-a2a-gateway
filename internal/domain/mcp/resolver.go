// Package mcp — MCP-as-a-Service add-on identity resolution (ADR-132 §10).
//
// A tenant subscribes to the MCP gateway add-on via POST /admin/mcp/{tenant_id}
// (httpadapter), which mints a per-tenant MCP API key — only the SHA-256 hash
// of the key (partner.HashAPIKey) plus a tool allowlist is persisted on the
// MCPConfig add-on record. External MCP clients (Claude Desktop, Cursor, ...)
// authenticate to chora-mcp-gateway with that key; the MCP gateway resolves it
// against this service over POST /admin/mcp/_resolve to obtain the acting
// Identity (clients/a2a_client.go resolverResponse).
//
// Identity model (CLAUDE.md §1 / ddd-enforcement.md §5):
//   - The add-on IS an A2A agent. Its AGID is the canonical, deterministic
//     MintAGID-derived identity for the tenant's MCP add-on
//     (agid:{tenant_id}:mcp:01) — an opaque PUBLIC identifier, NOT a credential
//     (the credential is the key hash) and NOT a GCID (agents hold no GCID).
//   - TenantID is the owning tenant of the add-on key (the data scope the agent
//     acts within). It is NOT a GCID and NOT a TenantMembership of the agent;
//     the MCP dispatcher propagates it as X-Tenant-Id and an empty value is a
//     hard failure — so this package refuses to emit a tenant-less identity.
//   - Scopes are the granted MCP tool allowlist (the capability gate input).
//   - A resolved (200) Identity always has Active=true. Two distinct failure
//     states sit below the Store: a permanently revoked (soft-deleted)
//     add-on never reaches the resolver at all (the Store filters it,
//     surfacing as ErrInvalidKey/401), while an administratively suspended
//     -but-not-revoked add-on DOES reach the resolver and surfaces as the
//     distinct ErrInactive/403 — the reversible pause the frozen wire
//     contract calls "key resolved but partner inactive."
package mcp

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/partner"
)

// addOnCapability + addOnInstance compose the MCP add-on's canonical AGID via
// partner.MintAGID(tenantID, addOnCapability, addOnInstance). The add-on is a
// single per-tenant agent, so the instance is fixed.
const (
	addOnCapability = "mcp"
	addOnInstance   = "01"
)

// Sentinel errors.
var (
	// ErrMissingKey — the caller supplied a blank API key (400 upstream).
	ErrMissingKey = errors.New("mcp: API key required")
	// ErrInvalidKey — the key does not resolve to a live add-on (401/404
	// upstream, with NO identity body).
	ErrInvalidKey = errors.New("mcp: API key invalid")
	// ErrInactive — the key resolves to a real, non-revoked add-on that is
	// administratively suspended (403 upstream, with NO identity body).
	// Distinct from ErrInvalidKey so the caller can tell "known key, paused"
	// from "unknown key" (chora-mcp-gateway's A2AClient already branches on
	// this via auth.ErrPartnerInactive).
	ErrInactive = errors.New("mcp: add-on suspended")
	// ErrNotFound is the Store sentinel for "no live add-on with this hash".
	// The Resolver maps it to ErrInvalidKey (callers never distinguish them).
	ErrNotFound = errors.New("mcp: add-on not found")
)

// Identity is the resolved MCP add-on identity returned to chora-mcp-gateway.
// Field semantics mirror chora-mcp-gateway/internal/domain/auth.Identity. There
// is intentionally NO Gcid field — agents are AGID-only.
type Identity struct {
	AGID        string
	PartnerName string
	TenantID    string
	Scopes      []string
	Active      bool
}

// AddOn is the live per-tenant MCP add-on record a Store returns for a given
// API key hash (a domain value object; the persistence adapter maps its row
// into this). The Store only ever returns non-revoked add-ons — a
// permanently revoked (soft-deleted) row is never returned at all
// (ErrNotFound instead). Suspended is the reversible, admin-toggled pause
// distinct from revocation: a suspended add-on's key still resolves to a
// real row (Suspended=true) instead of disappearing.
type AddOn struct {
	TenantID  string
	Scopes    []string
	Suspended bool
}

// Store is the persistence port that looks up a live MCP add-on by the SHA-256
// hash of its API key. It MUST filter soft-deleted (revoked) rows and return
// ErrNotFound on a miss. Implemented by the inmem / pg repo adapters.
type Store interface {
	ByAPIKeyHash(ctx context.Context, keyHash string) (AddOn, error)
}

// Resolver resolves a plaintext MCP API key to an Identity.
type Resolver struct {
	store Store
}

// NewResolver wires a Store. A nil store is a wiring bug and panics (fail loud).
func NewResolver(s Store) *Resolver {
	if s == nil {
		panic("mcp: NewResolver requires a non-nil Store")
	}
	return &Resolver{store: s}
}

// Resolve hashes the plaintext key with the canonical credential digest
// (partner.HashAPIKey — the SAME hash the key was provisioned with, never an
// AGID-derived placeholder), looks up the owning add-on, and returns the acting
// Identity. It fails loud at every boundary:
//
//   - blank key            → ErrMissingKey
//   - no live add-on        → ErrInvalidKey (revoked keys land here too)
//   - store transport error → wrapped error (never a key sentinel)
//   - tenant-less add-on    → error (never a 200 tenant-less identity)
func (r *Resolver) Resolve(ctx context.Context, plaintextKey string) (Identity, error) {
	key := strings.TrimSpace(plaintextKey)
	if key == "" {
		return Identity{}, ErrMissingKey
	}

	addOn, err := r.store.ByAPIKeyHash(ctx, partner.HashAPIKey(key))
	if errors.Is(err, ErrNotFound) {
		return Identity{}, ErrInvalidKey
	}
	if err != nil {
		return Identity{}, fmt.Errorf("mcp: resolve add-on: %w", err)
	}

	tenantID := strings.TrimSpace(addOn.TenantID)
	if tenantID == "" {
		// Never emit a tenant-less identity: the MCP dispatcher treats an empty
		// tenant as a hard failure, and a blank data scope would be a forged-
		// scope bypass.
		return Identity{}, errors.New("mcp: resolved add-on has empty tenant_id — refusing to emit a tenant-less identity")
	}

	if addOn.Suspended {
		return Identity{}, ErrInactive
	}

	agid, err := partner.MintAGID(tenantID, addOnCapability, addOnInstance)
	if err != nil {
		return Identity{}, fmt.Errorf("mcp: mint add-on AGID: %w", err)
	}

	return Identity{
		AGID:        agid,
		PartnerName: addOnPartnerName(tenantID),
		TenantID:    tenantID,
		Scopes:      append([]string(nil), addOn.Scopes...),
		Active:      true,
	}, nil
}

// addOnPartnerName is the human-readable display label for a tenant's MCP
// add-on. PartnerName is display-only and never an authority claim, so a
// truthful descriptive label (not a fabricated org name) is appropriate.
func addOnPartnerName(tenantID string) string {
	return "MCP Add-on (" + tenantID + ")"
}
