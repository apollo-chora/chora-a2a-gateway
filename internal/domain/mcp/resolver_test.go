// Package mcp_test — resolver_test.go: MCP-as-a-Service add-on key resolution.
//
// The Resolver turns a plaintext MCP API key into the acting Identity the
// chora-mcp-gateway needs (agid + owning tenant + tool scopes + active). It
// hashes the key with the REAL credential hash (partner.HashAPIKey — the same
// digest minted at provisioning, never an AGID-derived placeholder) and gates
// fail-loud: blank key, unknown key, and tenant-less rows never yield a
// success identity.
package mcp_test

import (
	"context"
	"errors"
	"testing"

	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/mcp"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/partner"
)

// stubStore is an in-test mcp.Store capturing the hash it is queried with.
type stubStore struct {
	gotHash string
	addOn   mcp.AddOn
	err     error
}

func (s *stubStore) ByAPIKeyHash(_ context.Context, keyHash string) (mcp.AddOn, error) {
	s.gotHash = keyHash
	if s.err != nil {
		return mcp.AddOn{}, s.err
	}
	return s.addOn, nil
}

func TestResolve_HappyPath_BuildsCanonicalIdentity(t *testing.T) {
	t.Parallel()
	const tenant = "0190aaaa-bbbb-7ccc-8ddd-eeeeeeeeeeee"
	store := &stubStore{addOn: mcp.AddOn{TenantID: tenant, Scopes: []string{"atom_search", "course_catalog"}}}
	r := mcp.NewResolver(store)

	id, err := r.Resolve(context.Background(), "plaintext-key-123")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	// AGID is the canonical MintAGID-derived add-on identity (agid:{tenant}:mcp:01).
	wantAGID, _ := partner.MintAGID(tenant, "mcp", "01")
	if id.AGID != wantAGID {
		t.Errorf("AGID = %q; want %q", id.AGID, wantAGID)
	}
	if id.TenantID != tenant {
		t.Errorf("TenantID = %q; want %q", id.TenantID, tenant)
	}
	if !id.Active {
		t.Error("Active = false; a resolved (non-revoked) add-on must be active")
	}
	if len(id.Scopes) != 2 || id.Scopes[0] != "atom_search" || id.Scopes[1] != "course_catalog" {
		t.Errorf("Scopes = %v; want [atom_search course_catalog]", id.Scopes)
	}
	if id.PartnerName == "" {
		t.Error("PartnerName empty; want a descriptive display label")
	}

	// The store MUST be queried with the REAL credential hash, never the
	// plaintext key and never an AGID-derived placeholder.
	if want := partner.HashAPIKey("plaintext-key-123"); store.gotHash != want {
		t.Errorf("store queried with %q; want HashAPIKey(plaintext) %q", store.gotHash, want)
	}
	if store.gotHash == "plaintext-key-123" {
		t.Error("store queried with PLAINTEXT key — the key MUST be hashed first")
	}
}

func TestResolve_BlankKey_ErrMissingKey(t *testing.T) {
	t.Parallel()
	r := mcp.NewResolver(&stubStore{})
	if _, err := r.Resolve(context.Background(), "   "); !errors.Is(err, mcp.ErrMissingKey) {
		t.Errorf("err = %v; want ErrMissingKey", err)
	}
}

func TestResolve_UnknownKey_ErrInvalidKey(t *testing.T) {
	t.Parallel()
	r := mcp.NewResolver(&stubStore{err: mcp.ErrNotFound})
	if _, err := r.Resolve(context.Background(), "nope"); !errors.Is(err, mcp.ErrInvalidKey) {
		t.Errorf("err = %v; want ErrInvalidKey", err)
	}
}

func TestResolve_StoreError_WrappedNotSentinel(t *testing.T) {
	t.Parallel()
	boom := errors.New("db down")
	r := mcp.NewResolver(&stubStore{err: boom})
	_, err := r.Resolve(context.Background(), "key")
	if err == nil {
		t.Fatal("expected an error for a failing store; got nil")
	}
	if errors.Is(err, mcp.ErrInvalidKey) || errors.Is(err, mcp.ErrMissingKey) {
		t.Errorf("store transport failure must not masquerade as a key sentinel: %v", err)
	}
}

func TestResolve_EmptyTenant_FailsLoud(t *testing.T) {
	t.Parallel()
	// A row with a blank tenant must NEVER yield a 200 identity — the MCP
	// dispatcher treats an empty tenant as a hard failure, and a blank scope
	// here would be a forged-scope bypass.
	r := mcp.NewResolver(&stubStore{addOn: mcp.AddOn{TenantID: "   ", Scopes: []string{"atom_search"}}})
	_, err := r.Resolve(context.Background(), "key")
	if err == nil {
		t.Fatal("expected a fail-loud error for empty tenant; got nil")
	}
	if errors.Is(err, mcp.ErrInvalidKey) {
		t.Errorf("empty-tenant must be a distinct fail-loud error, not ErrInvalidKey: %v", err)
	}
}

func TestResolve_SuspendedAddOn_ErrInactive(t *testing.T) {
	t.Parallel()
	// A suspended (but not revoked) add-on still resolves a real row — the
	// Resolver must turn that into the distinct ErrInactive sentinel (403
	// upstream) rather than conflating it with an unknown key (401).
	store := &stubStore{addOn: mcp.AddOn{TenantID: "t1", Scopes: []string{"atom_search"}, Suspended: true}}
	_, err := mcp.NewResolver(store).Resolve(context.Background(), "key")
	if !errors.Is(err, mcp.ErrInactive) {
		t.Errorf("err = %v; want ErrInactive for a suspended add-on", err)
	}
	if errors.Is(err, mcp.ErrInvalidKey) {
		t.Errorf("suspended must be distinct from ErrInvalidKey: %v", err)
	}
}

func TestResolve_ScopesAreCopied_NotAliased(t *testing.T) {
	t.Parallel()
	scopes := []string{"atom_search"}
	store := &stubStore{addOn: mcp.AddOn{TenantID: "t1", Scopes: scopes}}
	id, err := mcp.NewResolver(store).Resolve(context.Background(), "key")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	id.Scopes[0] = "MUTATED"
	if scopes[0] != "atom_search" {
		t.Error("Resolve returned an aliased scopes slice; mutating it corrupted the store input")
	}
}

func TestNewResolver_NilStore_Panics(t *testing.T) {
	t.Parallel()
	defer func() {
		if recover() == nil {
			t.Error("NewResolver(nil) must panic (fail loud) — a nil store is a wiring bug")
		}
	}()
	_ = mcp.NewResolver(nil)
}
