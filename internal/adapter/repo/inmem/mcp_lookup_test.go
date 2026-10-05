// Package inmem_test — mcp_lookup_test.go: MCPConfigRepo.ByAPIKeyHash, the
// reverse lookup (key hash → add-on) backing POST /admin/mcp/_resolve. It
// implements the domain mcp.Store port: returns a domain mcp.AddOn on a live
// match, skips soft-deleted rows, and returns mcp.ErrNotFound on a miss.
package inmem_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/repo/inmem"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/mcp"
)

func TestMCPConfigRepo_ByAPIKeyHash_FindsLiveAddOn(t *testing.T) {
	t.Parallel()
	r := inmem.NewMCPConfigRepo()
	now := time.Now().UTC()
	_ = r.Put(&inmem.MCPConfig{
		TenantID:     "tenant-1",
		APIKeyHash:   "hash-1",
		AllowedTools: []string{"atom_search", "course_catalog"},
		CreatedAt:    now,
		UpdatedAt:    now,
	})

	got, err := r.ByAPIKeyHash(context.Background(), "hash-1")
	if err != nil {
		t.Fatalf("ByAPIKeyHash: %v", err)
	}
	if got.TenantID != "tenant-1" {
		t.Errorf("TenantID = %q; want tenant-1", got.TenantID)
	}
	if len(got.Scopes) != 2 {
		t.Errorf("Scopes = %v; want 2", got.Scopes)
	}
	// Returned scopes must be a copy, not an alias of the stored slice.
	got.Scopes[0] = "MUTATED"
	again, _ := r.ByAPIKeyHash(context.Background(), "hash-1")
	if again.Scopes[0] != "atom_search" {
		t.Error("ByAPIKeyHash returned an aliased scopes slice")
	}
}

func TestMCPConfigRepo_ByAPIKeyHash_MissReturnsErrNotFound(t *testing.T) {
	t.Parallel()
	r := inmem.NewMCPConfigRepo()
	_, err := r.ByAPIKeyHash(context.Background(), "absent")
	if !errors.Is(err, mcp.ErrNotFound) {
		t.Errorf("err = %v; want mcp.ErrNotFound", err)
	}
}

func TestMCPConfigRepo_ByAPIKeyHash_SkipsSoftDeleted(t *testing.T) {
	t.Parallel()
	r := inmem.NewMCPConfigRepo()
	now := time.Now().UTC()
	_ = r.Put(&inmem.MCPConfig{
		TenantID:   "tenant-del",
		APIKeyHash: "hash-del",
		CreatedAt:  now,
		UpdatedAt:  now,
		DeletedAt:  &now, // revoked
	})
	if _, err := r.ByAPIKeyHash(context.Background(), "hash-del"); !errors.Is(err, mcp.ErrNotFound) {
		t.Errorf("err = %v; want mcp.ErrNotFound for a soft-deleted add-on", err)
	}
}

func TestMCPConfigRepo_ByAPIKeyHash_PropagatesSuspended(t *testing.T) {
	t.Parallel()
	r := inmem.NewMCPConfigRepo()
	now := time.Now().UTC()
	_ = r.Put(&inmem.MCPConfig{
		TenantID:   "tenant-susp",
		APIKeyHash: "hash-susp",
		Suspended:  true, // paused, NOT revoked — the row must still resolve
		CreatedAt:  now,
		UpdatedAt:  now,
	})
	got, err := r.ByAPIKeyHash(context.Background(), "hash-susp")
	if err != nil {
		t.Fatalf("ByAPIKeyHash: %v", err)
	}
	if !got.Suspended {
		t.Error("Suspended = false; want true (a suspended row must still resolve, marked inactive)")
	}
}

func TestMCPConfigRepo_SetSuspended_TogglesAndIsVisibleViaByAPIKeyHash(t *testing.T) {
	t.Parallel()
	r := inmem.NewMCPConfigRepo()
	now := time.Now().UTC()
	_ = r.Put(&inmem.MCPConfig{TenantID: "t1", APIKeyHash: "h1", CreatedAt: now, UpdatedAt: now})

	if err := r.SetSuspended("t1", true); err != nil {
		t.Fatalf("SetSuspended(true): %v", err)
	}
	got, err := r.ByAPIKeyHash(context.Background(), "h1")
	if err != nil {
		t.Fatalf("ByAPIKeyHash after suspend: %v", err)
	}
	if !got.Suspended {
		t.Error("expected Suspended=true after SetSuspended(t1, true)")
	}

	if err := r.SetSuspended("t1", false); err != nil {
		t.Fatalf("SetSuspended(false): %v", err)
	}
	got, err = r.ByAPIKeyHash(context.Background(), "h1")
	if err != nil {
		t.Fatalf("ByAPIKeyHash after reinstate: %v", err)
	}
	if got.Suspended {
		t.Error("expected Suspended=false after SetSuspended(t1, false) (reinstate)")
	}
}

func TestMCPConfigRepo_SetSuspended_UnknownTenant_ErrNotFound(t *testing.T) {
	t.Parallel()
	r := inmem.NewMCPConfigRepo()
	if err := r.SetSuspended("absent", true); !errors.Is(err, inmem.ErrNotFound) {
		t.Errorf("err = %v; want inmem.ErrNotFound", err)
	}
}

func TestMCPConfigRepo_SetSuspended_RevokedTenant_ErrNotFound(t *testing.T) {
	t.Parallel()
	// A hard-revoked config cannot be re-toggled through SetSuspended — that
	// would resurrect a permanently revoked add-on through a side door.
	r := inmem.NewMCPConfigRepo()
	now := time.Now().UTC()
	_ = r.Put(&inmem.MCPConfig{
		TenantID: "t1", APIKeyHash: "h1", CreatedAt: now, UpdatedAt: now, DeletedAt: &now,
	})
	if err := r.SetSuspended("t1", true); !errors.Is(err, inmem.ErrNotFound) {
		t.Errorf("err = %v; want inmem.ErrNotFound for a revoked config", err)
	}
}
