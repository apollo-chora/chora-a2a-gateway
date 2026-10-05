// Package pg_test — unit tests for the pgx-backed IdentityStore (W0-F1,
// CHO-2198): durable persistence for the ExternalAgentIdentity aggregate
// (partner public-key PEM + SHA-256 fingerprint) surfaced by the O+ A2A
// console. Reuses the shared stubQuerier harness from repo_test.go.
//
// CRITICAL invariants asserted:
//
//   - Put emits an UPSERT keyed on the agid natural key; the tenant bound at
//     construction is the tenant_id bind (mirrors RegistrationStore).
//   - Get filters `deleted_at IS NULL`, binds the construction tenant, and
//     maps ErrNoRows → repo.ErrNotFound.
//   - No SQL references a `gcid` column (AGID ≠ GCID; CLAUDE.md §1).
package pg_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/repo"
	pgrepo "github.com/apollo-chora/chora-a2a-gateway/internal/adapter/repo/pg"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/agent_identity"
)

const testPEM = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAtesttesttesttesttesttesttesttesttesttestt=\n-----END PUBLIC KEY-----"

func seedIdentity(t *testing.T) *agent_identity.ExternalAgentIdentity {
	t.Helper()
	id, err := agent_identity.New(agent_identity.NewParams{
		AGID:         "agid:01970000-0000-7000-a000-000000000001:recommend_content:0",
		PublicKeyPEM: testPEM,
		JWKSURI:      "https://partner.example/.well-known/jwks.json",
		Algorithm:    agent_identity.AlgEd25519,
	})
	if err != nil {
		t.Fatalf("seed identity: %v", err)
	}
	return id
}

func TestIdentityStore_Put_EmitsUpsertSQL(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{}
	tenantID := uuid.NewString()
	store := pgrepo.NewIdentityStore(q, tenantID)
	id := seedIdentity(t)

	if err := store.Put(id); err != nil {
		t.Fatalf("Put: %v", err)
	}
	call, ok := findCall(q, "external_agent_identities")
	if !ok {
		t.Fatalf("expected INSERT INTO external_agent_identities; calls: %+v", q.calls)
	}
	if !strings.Contains(call.sql, "ON CONFLICT") {
		t.Errorf("expected UPSERT (ON CONFLICT (agid)); got:\n%s", call.sql)
	}
	assertNoGcidColumn(t, call.sql)
	if call.args[0] != id.AGID {
		t.Errorf("arg[0] = %v; want agid %q", call.args[0], id.AGID)
	}
	if call.args[1] != tenantID {
		t.Errorf("arg[1] = %v; want bound tenant %q", call.args[1], tenantID)
	}
}

func TestIdentityStore_Put_RejectsInvalid(t *testing.T) {
	t.Parallel()
	store := pgrepo.NewIdentityStore(&stubQuerier{}, uuid.NewString())
	if err := store.Put(nil); err == nil {
		t.Error("expected error on nil identity")
	}
	if err := store.Put(&agent_identity.ExternalAgentIdentity{AGID: "", PublicKeyPEM: testPEM}); err == nil {
		t.Error("expected error on empty AGID")
	}
	if err := store.Put(&agent_identity.ExternalAgentIdentity{AGID: "agid:x:y:0", PublicKeyPEM: ""}); err == nil {
		t.Error("expected error on empty PublicKeyPEM")
	}
}

func TestIdentityStore_Get_FiltersSoftDeletedAndBindsTenant(t *testing.T) {
	t.Parallel()
	tenantID := uuid.NewString()
	q := &stubQuerier{
		rowScanners: []func(dest ...any) error{
			func(dest ...any) error {
				*(dest[0].(*string)) = "agid:x:recommend_content:0"
				*(dest[1].(*string)) = testPEM
				*(dest[2].(*string)) = strings.Repeat("c", 64)
				*(dest[3].(*string)) = "https://p.example/jwks.json"
				*(dest[4].(*string)) = "Ed25519"
				*(dest[5].(*time.Time)) = time.Now().UTC()
				*(dest[6].(*time.Time)) = time.Now().UTC()
				return nil
			},
		},
	}
	store := pgrepo.NewIdentityStore(q, tenantID)
	got, err := store.Get("agid:x:recommend_content:0")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Algorithm != agent_identity.AlgEd25519 {
		t.Errorf("Algorithm = %q; want Ed25519", got.Algorithm)
	}
	call, ok := findCall(q, "FROM external_agent_identities")
	if !ok {
		t.Fatalf("expected SELECT FROM external_agent_identities; calls: %+v", q.calls)
	}
	if !strings.Contains(call.sql, "deleted_at IS NULL") {
		t.Errorf("Get must filter deleted_at IS NULL. SQL:\n%s", call.sql)
	}
	if call.args[0] != tenantID {
		t.Errorf("Get arg[0] = %v; want bound tenant %q (RLS defence-in-depth)", call.args[0], tenantID)
	}
	assertNoGcidColumn(t, call.sql)
}

func TestIdentityStore_Get_ReturnsErrNotFound_OnMiss(t *testing.T) {
	t.Parallel()
	store := pgrepo.NewIdentityStore(&stubQuerier{}, uuid.NewString())
	if _, err := store.Get("agid:absent:x:0"); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("expected repo.ErrNotFound on miss; got %v", err)
	}
}

// Compile-time proof the pg adapter satisfies the port.
var _ repo.IdentityStore = (*pgrepo.IdentityStore)(nil)
