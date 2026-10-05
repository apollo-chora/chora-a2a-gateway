// mcpconfig.go implements the M12 chora_a2a Postgres-backed adapter for
// chora-a2a-gateway's MCPConfigStore port (internal/adapter/repo/ports.go),
// replacing the in-memory-only internal/adapter/repo/inmem.MCPConfigRepo
// for production. This closes the "MCP partner keys wiped on restart" gap:
// MCPConfigRepo previously held every registered MCP add-on (tenant -> API
// key hash + tool allowlist) in a plain Go map with no durability across a
// pod restart/rollout.
//
// Architecture notes:
//
//   - Reuses the local pg.Querier interface from
//     internal/adapter/pg/runtime.go, exactly like RegistrationStore /
//     ContractStore / InvocationStore in repo.go, so unit tests
//     (mcpconfig_test.go) stub the SQL surface without a live Postgres
//     connection.
//   - Unlike RegistrationStore/ContractStore/InvocationStore, MCPConfigStore
//     is NOT constructed with a bound tenantID: an MCP add-on config is
//     inherently keyed BY tenant (Put/Get/SetSuspended all take tenant_id
//     per call), mirroring internal/adapter/repo/inmem.MCPConfigRepo
//     exactly, rather than the whole store belonging to one tenant.
//   - Pre-tenant lookup (ByAPIKeyHash): POST /admin/mcp/_resolve presents an
//     opaque partner API key and must discover WHICH tenant owns it — that
//     necessarily runs BEFORE any tenant context exists, so this is the
//     sole method here that does NOT bind a tenant_id filter. This mirrors
//     the mcp_configs RLS policy (migrations/0007_mcp_configs.up.sql),
//     which — like partner_registrations / a2a_contracts / a2a_invocations
//     added in 0006_oplus_repos.up.sql — falls through to permissive when
//     the chora.tenant_id GUC is unset. That GUC is in fact NEVER set by
//     the current pg wiring (internal/adapter/pg/runtime.go's
//     PgxPoolQuerier issues bare pool.Exec/Query, no `SET LOCAL`
//     transaction wrapper), so every tenant-scoped query in this package
//     ALREADY relies on the bound `tenant_id = $1` application-layer
//     parameter rather than RLS for enforcement (see repo.go's package
//     doc). ByAPIKeyHash simply omits that parameter where the other
//     methods supply it. This is NOT the ADR-165/ADR-184 WithRLSBypass(ctx)
//     mechanism (ddd-enforcement.md's two ADR-scoped surfaces are
//     unrelated) and does not add a 3rd RLS-bypass surface: no code path
//     anywhere in this service today ever sets chora.tenant_id in the
//     first place, so there is nothing to bypass.
//   - Soft-delete: Get/ByAPIKeyHash both filter `deleted_at IS NULL`. Put is
//     a full-row upsert — a fresh POST /admin/mcp/{tenant_id} always mints
//     a brand-new key + allowlist and clears any prior suspend/revoke
//     state, mirroring inmem.MCPConfigRepo.Put's full-replace semantics
//     (see internal/adapter/http/ext_router.go's mcpRoutes handler).
//   - SetSuspended existence check: the shared pg.Querier.Exec signature
//     (internal/adapter/pg/runtime.go) returns only `error`, not an
//     affected-row count, so there is no direct way to detect "UPDATE
//     matched zero rows" from Exec alone. SetSuspended therefore does a
//     Get-then-UPDATE: an admin-triggered, low-frequency toggle can afford
//     the extra read, and it reproduces inmem.MCPConfigRepo.SetSuspended's
//     exact contract — ErrNotFound for both an absent AND an
//     already-revoked tenant, since revocation is permanent and is never
//     resurrected through this side door.
package pg

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	chorapg "github.com/apollo-chora/chora-a2a-gateway/internal/adapter/pg"
	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/repo"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/mcp"
)

// MCPConfigStore is the pgx-backed implementation of the
// repo.MCPConfigStore port.
type MCPConfigStore struct {
	q chorapg.Querier
}

// NewMCPConfigStore wraps a Querier. Unlike NewRegistrationStore /
// NewContractStore / NewInvocationStore, no tenantID is bound at
// construction — see the package doc comment above.
func NewMCPConfigStore(q chorapg.Querier) *MCPConfigStore {
	return &MCPConfigStore{q: q}
}

// Put upserts the tenant's MCP add-on config. A fresh POST
// /admin/mcp/{tenant_id} always mints a brand-new key + allowlist and
// replaces the row wholesale (including clearing suspended/deleted_at),
// matching inmem.MCPConfigRepo.Put.
//
// SECURITY: api_key_hash MUST carry the real SHA-256 digest of the minted
// credential (partner.HashAPIKey), never a blank placeholder — a config
// reaching Put with an empty hash is a programmer error and is rejected
// loudly, mirroring internal/adapter/pg/partner_repository.go's Put guard.
func (r *MCPConfigStore) Put(c *repo.MCPConfig) error {
	if c == nil {
		return errors.New("pg.MCPConfigStore.Put: nil config")
	}
	if strings.TrimSpace(c.TenantID) == "" {
		return errors.New("pg.MCPConfigStore.Put: TenantID required")
	}
	if strings.TrimSpace(c.APIKeyHash) == "" {
		return fmt.Errorf("pg.MCPConfigStore.Put: tenant %q has empty APIKeyHash — refusing to persist a blank/forgeable credential hash", c.TenantID)
	}
	const q = `
INSERT INTO mcp_configs (
    tenant_id, api_key_hash, allowed_tools, suspended,
    created_at, updated_at, deleted_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7
)
ON CONFLICT (tenant_id) DO UPDATE SET
    api_key_hash  = EXCLUDED.api_key_hash,
    allowed_tools = EXCLUDED.allowed_tools,
    suspended     = EXCLUDED.suspended,
    updated_at    = EXCLUDED.updated_at,
    deleted_at    = EXCLUDED.deleted_at
`
	return r.q.Exec(context.Background(), q,
		c.TenantID,
		c.APIKeyHash,
		c.AllowedTools,
		c.Suspended,
		c.CreatedAt,
		c.UpdatedAt,
		nullableTimePtr(c.DeletedAt),
	)
}

const mcpConfigSelectColumns = `
    tenant_id, api_key_hash, allowed_tools, suspended,
    created_at, updated_at, deleted_at
`

// Get fetches the live (non-revoked) config for a tenant. Returns
// ErrNotFound on miss.
func (r *MCPConfigStore) Get(tenantID string) (*repo.MCPConfig, error) {
	q := `SELECT ` + mcpConfigSelectColumns + `
FROM mcp_configs
WHERE tenant_id = $1 AND deleted_at IS NULL
`
	row := r.q.QueryRow(context.Background(), q, tenantID)
	return scanMCPConfig(row)
}

// ByAPIKeyHash implements mcp.Store: the pre-tenant reverse lookup from a
// SHA-256 API key hash to the live add-on that owns it. Deliberately NOT
// tenant-scoped (see package doc comment). Soft-deleted (revoked) rows are
// excluded by the query itself; a miss maps to the mcp package's own
// ErrNotFound sentinel (NOT repo.ErrNotFound) because
// internal/domain/mcp.Resolver.Resolve matches errors against mcp.ErrNotFound
// specifically.
func (r *MCPConfigStore) ByAPIKeyHash(ctx context.Context, keyHash string) (mcp.AddOn, error) {
	q := `SELECT ` + mcpConfigSelectColumns + `
FROM mcp_configs
WHERE api_key_hash = $1 AND deleted_at IS NULL
`
	row := r.q.QueryRow(ctx, q, keyHash)
	cfg, err := scanMCPConfig(row)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return mcp.AddOn{}, mcp.ErrNotFound
		}
		return mcp.AddOn{}, err
	}
	return mcp.AddOn{
		TenantID:  cfg.TenantID,
		Scopes:    append([]string(nil), cfg.AllowedTools...),
		Suspended: cfg.Suspended,
	}, nil
}

// SetSuspended toggles the reversible admin pause on a live (non-revoked)
// config — backs /admin/mcp/{tenant_id}:suspend and :reinstate. Returns
// ErrNotFound for an absent OR already-revoked tenant: revocation is
// permanent, so a hard-revoked add-on cannot be resurrected through this
// side door (a fresh POST /admin/mcp/{tenant_id} is required instead). See
// the package doc comment for why this is a Get-then-UPDATE rather than a
// rows-affected check.
func (r *MCPConfigStore) SetSuspended(tenantID string, suspended bool) error {
	if _, err := r.Get(tenantID); err != nil {
		return err
	}
	const q = `
UPDATE mcp_configs
SET suspended = $2
WHERE tenant_id = $1 AND deleted_at IS NULL
`
	return r.q.Exec(context.Background(), q, tenantID, suspended)
}

func scanMCPConfig(row chorapg.Row) (*repo.MCPConfig, error) {
	var (
		cfg          repo.MCPConfig
		allowedTools []string
		deletedAt    *time.Time
	)
	err := row.Scan(
		&cfg.TenantID,
		&cfg.APIKeyHash,
		&allowedTools,
		&cfg.Suspended,
		&cfg.CreatedAt,
		&cfg.UpdatedAt,
		&deletedAt,
	)
	if err != nil {
		if errors.Is(err, chorapg.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("pg.MCPConfigStore.scan: %w", err)
	}
	cfg.AllowedTools = allowedTools
	cfg.CreatedAt = cfg.CreatedAt.UTC()
	cfg.UpdatedAt = cfg.UpdatedAt.UTC()
	if deletedAt != nil {
		t := deletedAt.UTC()
		cfg.DeletedAt = &t
	}
	return &cfg, nil
}
