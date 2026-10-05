// Package pg_test — unit tests for the pgx-backed MCPConfigStore
// implementation (mcpconfig.go).
//
// Per [[feedback-no-stubs-real-wiring]]: these are stub-Querier unit tests
// (no live DB), matching repo_test.go's convention for RegistrationStore /
// ContractStore / InvocationStore — this package has no build-tag-gated
// live-DB integration suite.
//
// CRITICAL invariants asserted here:
//
//   - ByAPIKeyHash — the pre-tenant reverse lookup — MUST NOT bind a
//     tenant_id filter (it resolves WHICH tenant owns the key, so the
//     tenant is unknown going in). Every other method (Get/SetSuspended)
//     MUST bind tenant_id.
//   - ByAPIKeyHash misses return mcp.ErrNotFound (the domain mcp.Store
//     sentinel internal/domain/mcp.Resolver.Resolve matches against) — NOT
//     repo.ErrNotFound / pgrepo.ErrNotFound, which Get/SetSuspended use.
//   - Soft-delete: Get / ByAPIKeyHash both filter `deleted_at IS NULL`.
//   - SetSuspended returns repo.ErrNotFound (via a Get pre-check — see
//     mcpconfig.go doc comment for why) for both an absent AND an
//     already-revoked tenant, and never issues the UPDATE in that case.
package pg_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	chorapg "github.com/apollo-chora/chora-a2a-gateway/internal/adapter/pg"
	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/repo"
	pgrepo "github.com/apollo-chora/chora-a2a-gateway/internal/adapter/repo/pg"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/mcp"

	"github.com/google/uuid"
)

func TestMCPConfigStore_Put_EmitsUpsertSQL(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{}
	store := pgrepo.NewMCPConfigStore(q)
	now := time.Now().UTC()
	tenantID := uuid.NewString()

	cfg := &repo.MCPConfig{
		TenantID:     tenantID,
		APIKeyHash:   strings.Repeat("a", 64),
		AllowedTools: []string{"atom_search", "course_catalog"},
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := store.Put(cfg); err != nil {
		t.Fatalf("Put: %v", err)
	}
	call, ok := findCall(q, "mcp_configs")
	if !ok {
		t.Fatalf("expected INSERT INTO mcp_configs; calls: %+v", q.calls)
	}
	if !strings.Contains(call.sql, "ON CONFLICT") {
		t.Errorf("expected UPSERT (ON CONFLICT) in Put SQL; got:\n%s", call.sql)
	}
	assertNoGcidColumn(t, call.sql)
	if call.args[0] != tenantID {
		t.Errorf("arg[0] = %v; want tenant_id %q", call.args[0], tenantID)
	}
	if call.args[1] != cfg.APIKeyHash {
		t.Errorf("arg[1] = %v; want api_key_hash %q", call.args[1], cfg.APIKeyHash)
	}
}

func TestMCPConfigStore_Put_NilRejected(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{}
	store := pgrepo.NewMCPConfigStore(q)
	if err := store.Put(nil); err == nil {
		t.Fatal("expected error for nil config; got nil")
	}
}

// TestMCPConfigStore_Put_EmptyAPIKeyHash_FailsLoud mirrors
// internal/adapter/pg/partner_repository.go's Put guard: a config reaching
// Put with no credential hash is a programmer error (key never minted /
// dropped before persistence), and MUST be rejected loudly rather than
// silently persisting a blank/forgeable hash.
func TestMCPConfigStore_Put_EmptyAPIKeyHash_FailsLoud(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{}
	store := pgrepo.NewMCPConfigStore(q)
	cfg := &repo.MCPConfig{TenantID: uuid.NewString(), APIKeyHash: ""}
	if err := store.Put(cfg); err == nil {
		t.Fatal("expected fail-loud error for empty APIKeyHash; got nil")
	}
	if len(q.calls) != 0 {
		t.Errorf("expected no SQL emitted for a rejected Put; calls: %+v", q.calls)
	}
}

func TestMCPConfigStore_Put_EmptyTenantID_FailsLoud(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{}
	store := pgrepo.NewMCPConfigStore(q)
	cfg := &repo.MCPConfig{TenantID: "", APIKeyHash: strings.Repeat("a", 64)}
	if err := store.Put(cfg); err == nil {
		t.Fatal("expected fail-loud error for empty TenantID; got nil")
	}
}

func TestMCPConfigStore_Get_ReturnsErrNotFound_OnMiss(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{}
	store := pgrepo.NewMCPConfigStore(q)
	if _, err := store.Get(uuid.NewString()); !errors.Is(err, pgrepo.ErrNotFound) {
		t.Fatalf("expected ErrNotFound on miss; got %v", err)
	}
}

func TestMCPConfigStore_Get_FiltersTenantAndSoftDeleted(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{}
	store := pgrepo.NewMCPConfigStore(q)
	tenantID := uuid.NewString()
	_, _ = store.Get(tenantID)

	call, ok := findCall(q, "FROM mcp_configs")
	if !ok {
		t.Fatalf("expected SELECT FROM mcp_configs; calls: %+v", q.calls)
	}
	if !strings.Contains(call.sql, "tenant_id =") {
		t.Errorf("Get must filter on tenant_id column. SQL:\n%s", call.sql)
	}
	if !strings.Contains(call.sql, "deleted_at IS NULL") {
		t.Errorf("Get must filter deleted_at IS NULL. SQL:\n%s", call.sql)
	}
	if call.args[0] != tenantID {
		t.Errorf("arg[0] = %v; want tenant_id %q", call.args[0], tenantID)
	}
	assertNoGcidColumn(t, call.sql)
}

func TestMCPConfigStore_Get_ScansRowIntoConfig(t *testing.T) {
	t.Parallel()
	tenantID := uuid.NewString()
	createdAt := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	q := &stubQuerier{
		rowScanners: []func(dest ...any) error{
			func(dest ...any) error {
				// Mirrors mcpConfigSelectColumns ordering: tenant_id,
				// api_key_hash, allowed_tools, suspended, created_at,
				// updated_at, deleted_at.
				*(dest[0].(*string)) = tenantID
				*(dest[1].(*string)) = strings.Repeat("b", 64)
				*(dest[2].(*[]string)) = []string{"atom_search"}
				*(dest[3].(*bool)) = true
				*(dest[4].(*time.Time)) = createdAt
				*(dest[5].(*time.Time)) = createdAt
				*(dest[6].(**time.Time)) = nil
				return nil
			},
		},
	}
	store := pgrepo.NewMCPConfigStore(q)
	cfg, err := store.Get(tenantID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if cfg.TenantID != tenantID {
		t.Errorf("TenantID = %q; want %q", cfg.TenantID, tenantID)
	}
	if !cfg.Suspended {
		t.Errorf("Suspended = false; want true")
	}
	if len(cfg.AllowedTools) != 1 || cfg.AllowedTools[0] != "atom_search" {
		t.Errorf("AllowedTools = %v", cfg.AllowedTools)
	}
	if cfg.DeletedAt != nil {
		t.Errorf("DeletedAt = %v; want nil", cfg.DeletedAt)
	}
}

// -----------------------------------------------------------------------------
// ByAPIKeyHash — the pre-tenant reverse lookup (mcp.Store contract).
// -----------------------------------------------------------------------------

func TestMCPConfigStore_ByAPIKeyHash_DoesNotBindTenantID(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{}
	store := pgrepo.NewMCPConfigStore(q)
	_, _ = store.ByAPIKeyHash(context.Background(), "some-hash")

	call, ok := findCall(q, "FROM mcp_configs")
	if !ok {
		t.Fatalf("expected SELECT FROM mcp_configs; calls: %+v", q.calls)
	}
	// tenant_id legitimately appears in the SELECT column list (the caller
	// needs it in the returned AddOn) — what it MUST NOT do is FILTER on
	// tenant_id, since the whole point of this lookup is that the tenant is
	// not known yet.
	whereClause := call.sql[strings.Index(call.sql, "WHERE"):]
	if strings.Contains(whereClause, "tenant_id") {
		t.Errorf("ByAPIKeyHash is the pre-tenant lookup — its WHERE clause MUST NOT reference tenant_id. SQL:\n%s", call.sql)
	}
	if !strings.Contains(call.sql, "api_key_hash =") {
		t.Errorf("ByAPIKeyHash must filter on api_key_hash column. SQL:\n%s", call.sql)
	}
	if !strings.Contains(call.sql, "deleted_at IS NULL") {
		t.Errorf("ByAPIKeyHash must filter deleted_at IS NULL. SQL:\n%s", call.sql)
	}
	// Exactly one bind arg: the key hash. No tenant_id parameter at all.
	if len(call.args) != 1 || call.args[0] != "some-hash" {
		t.Errorf("args = %v; want exactly [\"some-hash\"]", call.args)
	}
	assertNoGcidColumn(t, call.sql)
}

func TestMCPConfigStore_ByAPIKeyHash_FindsLiveAddOn(t *testing.T) {
	t.Parallel()
	tenantID := uuid.NewString()
	now := time.Now().UTC()
	q := &stubQuerier{
		rowScanners: []func(dest ...any) error{
			func(dest ...any) error {
				*(dest[0].(*string)) = tenantID
				*(dest[1].(*string)) = strings.Repeat("c", 64)
				*(dest[2].(*[]string)) = []string{"atom_search", "course_catalog"}
				*(dest[3].(*bool)) = false
				*(dest[4].(*time.Time)) = now
				*(dest[5].(*time.Time)) = now
				*(dest[6].(**time.Time)) = nil
				return nil
			},
		},
	}
	store := pgrepo.NewMCPConfigStore(q)
	addOn, err := store.ByAPIKeyHash(context.Background(), "irrelevant-in-stub")
	if err != nil {
		t.Fatalf("ByAPIKeyHash: %v", err)
	}
	if addOn.TenantID != tenantID {
		t.Errorf("TenantID = %q; want %q", addOn.TenantID, tenantID)
	}
	if len(addOn.Scopes) != 2 {
		t.Errorf("Scopes = %v; want 2 entries", addOn.Scopes)
	}
	if addOn.Suspended {
		t.Errorf("Suspended = true; want false")
	}
}

// TestMCPConfigStore_ByAPIKeyHash_MissReturnsMCPErrNotFound is the
// review-critical sentinel-type assertion: ByAPIKeyHash implements
// mcp.Store, and internal/domain/mcp.Resolver.Resolve matches misses
// against mcp.ErrNotFound specifically (NOT repo.ErrNotFound/pgrepo.
// ErrNotFound, which every other method on this store returns).
func TestMCPConfigStore_ByAPIKeyHash_MissReturnsMCPErrNotFound(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{}
	store := pgrepo.NewMCPConfigStore(q)
	_, err := store.ByAPIKeyHash(context.Background(), "absent")
	if !errors.Is(err, mcp.ErrNotFound) {
		t.Errorf("err = %v; want mcp.ErrNotFound", err)
	}
	if errors.Is(err, pgrepo.ErrNotFound) {
		t.Errorf("err = %v; must NOT also satisfy pgrepo.ErrNotFound (distinct sentinel from mcp.ErrNotFound)", err)
	}
}

func TestMCPConfigStore_ByAPIKeyHash_PropagatesSuspended(t *testing.T) {
	t.Parallel()
	tenantID := uuid.NewString()
	now := time.Now().UTC()
	q := &stubQuerier{
		rowScanners: []func(dest ...any) error{
			func(dest ...any) error {
				*(dest[0].(*string)) = tenantID
				*(dest[1].(*string)) = strings.Repeat("d", 64)
				*(dest[2].(*[]string)) = []string{}
				*(dest[3].(*bool)) = true // suspended, NOT revoked
				*(dest[4].(*time.Time)) = now
				*(dest[5].(*time.Time)) = now
				*(dest[6].(**time.Time)) = nil
				return nil
			},
		},
	}
	store := pgrepo.NewMCPConfigStore(q)
	addOn, err := store.ByAPIKeyHash(context.Background(), "irrelevant-in-stub")
	if err != nil {
		t.Fatalf("ByAPIKeyHash: %v", err)
	}
	if !addOn.Suspended {
		t.Error("Suspended = false; want true (a suspended row must still resolve, marked inactive)")
	}
}

// -----------------------------------------------------------------------------
// SetSuspended
// -----------------------------------------------------------------------------

// TestMCPConfigStore_SetSuspended_TogglesViaGetThenUpdate documents the
// Get-then-UPDATE shape (see mcpconfig.go doc comment: the shared
// pg.Querier.Exec signature has no rows-affected signal, so an existence
// pre-check substitutes for it).
func TestMCPConfigStore_SetSuspended_TogglesViaGetThenUpdate(t *testing.T) {
	t.Parallel()
	tenantID := uuid.NewString()
	now := time.Now().UTC()
	q := &stubQuerier{
		rowScanners: []func(dest ...any) error{
			func(dest ...any) error {
				*(dest[0].(*string)) = tenantID
				*(dest[1].(*string)) = strings.Repeat("e", 64)
				*(dest[2].(*[]string)) = []string{}
				*(dest[3].(*bool)) = false
				*(dest[4].(*time.Time)) = now
				*(dest[5].(*time.Time)) = now
				*(dest[6].(**time.Time)) = nil
				return nil
			},
		},
	}
	store := pgrepo.NewMCPConfigStore(q)
	if err := store.SetSuspended(tenantID, true); err != nil {
		t.Fatalf("SetSuspended: %v", err)
	}
	updateCall, ok := findCall(q, "UPDATE mcp_configs")
	if !ok {
		t.Fatalf("expected an UPDATE mcp_configs call; calls: %+v", q.calls)
	}
	if !strings.Contains(updateCall.sql, "tenant_id =") {
		t.Errorf("SetSuspended UPDATE must filter on tenant_id. SQL:\n%s", updateCall.sql)
	}
	if !strings.Contains(updateCall.sql, "deleted_at IS NULL") {
		t.Errorf("SetSuspended UPDATE must filter deleted_at IS NULL. SQL:\n%s", updateCall.sql)
	}
	if updateCall.args[0] != tenantID || updateCall.args[1] != true {
		t.Errorf("UPDATE args = %v; want [%q, true]", updateCall.args, tenantID)
	}
}

func TestMCPConfigStore_SetSuspended_UnknownTenant_ErrNotFound(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{} // no rowScanners queued -> Get sees ErrNoRows
	store := pgrepo.NewMCPConfigStore(q)
	if err := store.SetSuspended(uuid.NewString(), true); !errors.Is(err, pgrepo.ErrNotFound) {
		t.Errorf("err = %v; want pgrepo.ErrNotFound", err)
	}
	if _, ok := findCall(q, "UPDATE mcp_configs"); ok {
		t.Error("SetSuspended must NOT issue the UPDATE when the pre-check Get misses")
	}
}

// TestMCPConfigStore_SetSuspended_RevokedTenant_ErrNotFound documents that a
// hard-revoked (soft-deleted) config cannot be re-toggled through
// SetSuspended. At the SQL level this collapses to the identical "miss" path
// as an unknown tenant, because Get's WHERE clause already filters
// deleted_at IS NULL — a revoked row simply never comes back from the
// database, so no separate code path is needed (or possible) to
// distinguish the two cases.
func TestMCPConfigStore_SetSuspended_RevokedTenant_ErrNotFound(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{} // deleted_at IS NULL means a revoked row never scans back
	store := pgrepo.NewMCPConfigStore(q)
	if err := store.SetSuspended(uuid.NewString(), true); !errors.Is(err, pgrepo.ErrNotFound) {
		t.Errorf("err = %v; want pgrepo.ErrNotFound for a revoked config", err)
	}
}

// -----------------------------------------------------------------------------
// port assertion
// -----------------------------------------------------------------------------

func TestMCPConfigStore_PortAssertion(t *testing.T) {
	t.Parallel()
	// Compile-time assertion (mirrors TestPortAssertions in repo_test.go);
	// runtime no-op.
	var _ repo.MCPConfigStore = pgrepo.NewMCPConfigStore((*nullQuerier)(nil))
	var _ mcp.Store = pgrepo.NewMCPConfigStore((*nullQuerier)(nil))
}

var _ chorapg.Querier = (*stubQuerier)(nil) // sanity: stub satisfies the real interface
