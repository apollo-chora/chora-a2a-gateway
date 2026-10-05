// Package pg_test — unit tests for the pgx-backed BYOAKeyStore (W0-F1,
// CHO-2198). Reuses the shared stubQuerier / findCall / assertNoGcidColumn
// harness from repo_test.go (same package).
//
// CRITICAL invariants asserted:
//
//   - Put emits an UPSERT keyed on the (tenant_id, provider) natural key and
//     never persists a blank/forgeable credential (empty ciphertext OR empty
//     fingerprint is rejected loudly — the durable-store analogue of
//     partner_repository.go's empty-APIKeyHash guard).
//   - Get filters `deleted_at IS NULL` and maps ErrNoRows → repo.ErrNotFound.
//   - SoftDelete tombstones a live row and returns ErrNotFound for an absent
//     OR already-revoked (tenant, provider) — mirrors MCPConfigStore.SetSuspended.
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
)

func liveBYOAEntry(tenantID string) *repo.BYOAKeyEntry {
	return &repo.BYOAKeyEntry{
		TenantID:       tenantID,
		Provider:       "openai",
		Ciphertext:     []byte{0x01, 0x02, 0x03, 0x04},
		KeyFingerprint: strings.Repeat("a", 64),
		RotatedAt:      time.Now().UTC(),
	}
}

func TestBYOAKeyStore_Put_EmitsUpsertSQL(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{}
	store := pgrepo.NewBYOAKeyStore(q)
	tenantID := uuid.NewString()
	e := liveBYOAEntry(tenantID)

	if err := store.Put(e); err != nil {
		t.Fatalf("Put: %v", err)
	}
	call, ok := findCall(q, "byoa_keys")
	if !ok {
		t.Fatalf("expected INSERT INTO byoa_keys; calls: %+v", q.calls)
	}
	if !strings.Contains(call.sql, "ON CONFLICT") {
		t.Errorf("expected UPSERT (ON CONFLICT (tenant_id, provider)); got:\n%s", call.sql)
	}
	if !strings.Contains(call.sql, "provider") {
		t.Errorf("expected provider column in upsert conflict target; got:\n%s", call.sql)
	}
	assertNoGcidColumn(t, call.sql)
	if call.args[0] != tenantID {
		t.Errorf("arg[0] = %v; want tenant %q", call.args[0], tenantID)
	}
	if call.args[1] != "openai" {
		t.Errorf("arg[1] = %v; want provider openai", call.args[1])
	}
}

func TestBYOAKeyStore_Put_RejectsBlankCredential(t *testing.T) {
	t.Parallel()
	tenantID := uuid.NewString()
	cases := map[string]func(*repo.BYOAKeyEntry){
		"empty ciphertext":  func(e *repo.BYOAKeyEntry) { e.Ciphertext = nil },
		"empty fingerprint": func(e *repo.BYOAKeyEntry) { e.KeyFingerprint = "" },
		"empty tenant":      func(e *repo.BYOAKeyEntry) { e.TenantID = "" },
		"empty provider":    func(e *repo.BYOAKeyEntry) { e.Provider = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			q := &stubQuerier{}
			store := pgrepo.NewBYOAKeyStore(q)
			e := liveBYOAEntry(tenantID)
			mutate(e)
			if err := store.Put(e); err == nil {
				t.Fatalf("%s: expected fail-loud rejection, got nil (SQL would persist a blank credential)", name)
			}
			if len(q.calls) != 0 {
				t.Errorf("%s: no SQL must fire for a rejected blank credential; calls: %+v", name, q.calls)
			}
		})
	}
}

func TestBYOAKeyStore_Put_RejectsNil(t *testing.T) {
	t.Parallel()
	store := pgrepo.NewBYOAKeyStore(&stubQuerier{})
	if err := store.Put(nil); err == nil {
		t.Fatal("expected error on nil entry")
	}
}

func TestBYOAKeyStore_Get_FiltersSoftDeleted(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		rowScanners: []func(dest ...any) error{
			func(dest ...any) error {
				*(dest[0].(*string)) = "tenant-x"
				*(dest[1].(*string)) = "openai"
				*(dest[2].(*[]byte)) = []byte{0x09}
				*(dest[3].(*string)) = strings.Repeat("b", 64)
				*(dest[4].(*time.Time)) = time.Now().UTC()
				*(dest[5].(**time.Time)) = nil
				return nil
			},
		},
	}
	store := pgrepo.NewBYOAKeyStore(q)
	got, err := store.Get("tenant-x", "openai")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Provider != "openai" {
		t.Errorf("Provider = %q; want openai", got.Provider)
	}
	call, ok := findCall(q, "FROM byoa_keys")
	if !ok {
		t.Fatalf("expected SELECT FROM byoa_keys; calls: %+v", q.calls)
	}
	if !strings.Contains(call.sql, "deleted_at IS NULL") {
		t.Errorf("Get must filter deleted_at IS NULL. SQL:\n%s", call.sql)
	}
	if call.args[0] != "tenant-x" || call.args[1] != "openai" {
		t.Errorf("Get args = %v; want [tenant-x openai]", call.args)
	}
	assertNoGcidColumn(t, call.sql)
}

func TestBYOAKeyStore_Get_ReturnsErrNotFound_OnMiss(t *testing.T) {
	t.Parallel()
	store := pgrepo.NewBYOAKeyStore(&stubQuerier{})
	if _, err := store.Get("tenant-x", "openai"); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("expected repo.ErrNotFound on miss; got %v", err)
	}
}

func TestBYOAKeyStore_SoftDelete_TombstonesLiveRow(t *testing.T) {
	t.Parallel()
	// Get-then-UPDATE: first QueryRow returns a live row, then an UPDATE fires.
	q := &stubQuerier{
		rowScanners: []func(dest ...any) error{
			func(dest ...any) error {
				*(dest[0].(*string)) = "tenant-x"
				*(dest[1].(*string)) = "openai"
				*(dest[2].(*[]byte)) = []byte{0x09}
				*(dest[3].(*string)) = strings.Repeat("b", 64)
				*(dest[4].(*time.Time)) = time.Now().UTC()
				*(dest[5].(**time.Time)) = nil
				return nil
			},
		},
	}
	store := pgrepo.NewBYOAKeyStore(q)
	if err := store.SoftDelete("tenant-x", "openai"); err != nil {
		t.Fatalf("SoftDelete: %v", err)
	}
	call, ok := findCall(q, "UPDATE byoa_keys")
	if !ok {
		t.Fatalf("expected UPDATE byoa_keys SET deleted_at; calls: %+v", q.calls)
	}
	if !strings.Contains(call.sql, "deleted_at") {
		t.Errorf("SoftDelete must set deleted_at. SQL:\n%s", call.sql)
	}
}

func TestBYOAKeyStore_SoftDelete_ErrNotFound_WhenAbsent(t *testing.T) {
	t.Parallel()
	// No rowScanners → the existence Get returns ErrNoRows → ErrNotFound; no UPDATE.
	q := &stubQuerier{}
	store := pgrepo.NewBYOAKeyStore(q)
	if err := store.SoftDelete("tenant-x", "openai"); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("expected repo.ErrNotFound for absent key; got %v", err)
	}
	if _, ok := findCall(q, "UPDATE byoa_keys"); ok {
		t.Error("no UPDATE must fire when the key is absent")
	}
}

// Compile-time proof the pg adapter satisfies the port.
var _ repo.BYOAKeyStore = (*pgrepo.BYOAKeyStore)(nil)
