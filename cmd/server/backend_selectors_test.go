// backend_selectors_test.go — env-driven backend selectors for the BYOA key
// vault + ExternalAgentIdentity store (W0-F1 durability twins of the O+/MCP
// repo selectors). Locks the fail-loud and inmem-default contracts so a nagging
// "swapped back to volatile storage" regression surfaces here, not in prod.
package main

import (
	"context"
	"strings"
	"testing"

	legacyinmem "github.com/apollo-chora/chora-a2a-gateway/internal/adapter/inmem"
	inmemrepo "github.com/apollo-chora/chora-a2a-gateway/internal/adapter/repo/inmem"
)

// ----------------------------------------------------------------------------
// chooseBYOAKeyBackend
// ----------------------------------------------------------------------------

// UNSET → inmem default (the pre-W0-F1 behaviour, kept as the explicit dev mode
// for BYOA keys that predates the CHO-2198 pg-durability pass).
func TestChooseBYOAKeyBackend_UnsetDefaultsToInmem(t *testing.T) {
	t.Setenv("CHORA_A2A_REPO_BACKEND", "")
	store, err := chooseBYOAKeyBackend(nil)
	if err != nil {
		t.Fatalf("unset default must not error; got %v", err)
	}
	if _, ok := store.(*inmemrepo.BYOAKeyRepo); !ok {
		t.Errorf("BYOA keys = %T; want *inmemrepo.BYOAKeyRepo", store)
	}
}

func TestChooseBYOAKeyBackend_ExplicitInmem(t *testing.T) {
	t.Setenv("CHORA_A2A_REPO_BACKEND", "INMEM")
	store, err := chooseBYOAKeyBackend(nil)
	if err != nil {
		t.Fatalf("explicit inmem must not error; got %v", err)
	}
	if _, ok := store.(*inmemrepo.BYOAKeyRepo); !ok {
		t.Errorf("BYOA keys = %T; want *inmemrepo.BYOAKeyRepo", store)
	}
}

// pg WITHOUT a pool must refuse (AUTH-state durability) rather than silently
// drop back to a volatile in-memory key vault.
func TestChooseBYOAKeyBackend_PGWithoutPoolFailsLoud(t *testing.T) {
	t.Setenv("CHORA_A2A_REPO_BACKEND", "pg")
	store, err := chooseBYOAKeyBackend(nil)
	if err == nil {
		t.Fatalf("backend=pg with nil pool must fail loud; got store=%+v", store)
	}
	if !strings.Contains(err.Error(), "pool unwired") {
		t.Errorf("error = %q; want pool-unwired guidance", err)
	}
	if store != nil {
		t.Errorf("fail-loud path must not return a store; got %+v", store)
	}
}

// Unrecognised value falls back to inmem with a loud WARNING (matching the
// pre-existing BYOA key behaviour), never an error.
func TestChooseBYOAKeyBackend_UnknownFallsBackToInmem(t *testing.T) {
	t.Setenv("CHORA_A2A_REPO_BACKEND", "redis")
	store, err := chooseBYOAKeyBackend(nil)
	if err != nil {
		t.Fatalf("unknown backend must not error for BYOA keys; got %v", err)
	}
	if _, ok := store.(*inmemrepo.BYOAKeyRepo); !ok {
		t.Errorf("BYOA keys = %T; want *inmemrepo.BYOAKeyRepo", store)
	}
}

// ----------------------------------------------------------------------------
// chooseIdentityBackend
// ----------------------------------------------------------------------------

func TestChooseIdentityBackend_UnsetDefaultsToInmem(t *testing.T) {
	t.Setenv("CHORA_A2A_REPO_BACKEND", "")
	store, err := chooseIdentityBackend(nil)
	if err != nil {
		t.Fatalf("unset default must not error; got %v", err)
	}
	if store == nil {
		t.Fatal("identity store must not be nil")
	}
}

func TestChooseIdentityBackend_ExplicitInmem(t *testing.T) {
	t.Setenv("CHORA_A2A_REPO_BACKEND", "INMEM")
	store, err := chooseIdentityBackend(nil)
	if err != nil {
		t.Fatalf("explicit inmem must not error; got %v", err)
	}
	if _, ok := store.(*legacyinmem.IdentityStore); !ok {
		t.Errorf("identity store = %T; want *legacyinmem.IdentityStore", store)
	}
}

func TestChooseIdentityBackend_PGWithoutPoolFailsLoud(t *testing.T) {
	t.Setenv("CHORA_A2A_REPO_BACKEND", "pg")
	store, err := chooseIdentityBackend(nil)
	if err == nil {
		t.Fatalf("backend=pg with nil pool must fail loud; got store=%+v", store)
	}
	if !strings.Contains(err.Error(), "pool unwired") {
		t.Errorf("error = %q; want pool-unwired guidance", err)
	}
	if store != nil {
		t.Errorf("fail-loud path must not return a store; got %+v", store)
	}
}

func TestChooseIdentityBackend_UnknownFallsBackToInmem(t *testing.T) {
	t.Setenv("CHORA_A2A_REPO_BACKEND", "redis")
	store, err := chooseIdentityBackend(nil)
	if err != nil {
		t.Fatalf("unknown backend must not error for identity store; got %v", err)
	}
	if _, ok := store.(*legacyinmem.IdentityStore); !ok {
		t.Errorf("identity store = %T; want *legacyinmem.IdentityStore", store)
	}
}

// ----------------------------------------------------------------------------
// outboxWorkerID
// ----------------------------------------------------------------------------

func TestOutboxWorkerID_EnvWinsOverHostname(t *testing.T) {
	t.Setenv("CHORA_OUTBOX_WORKER_ID", "worker-1")
	t.Setenv("HOSTNAME", "pod-a")
	if got := outboxWorkerID(); got != "worker-1" {
		t.Errorf("outboxWorkerID = %q; want worker-1 (env wins)", got)
	}
}

func TestOutboxWorkerID_HostnameFallback(t *testing.T) {
	t.Setenv("CHORA_OUTBOX_WORKER_ID", "")
	t.Setenv("HOSTNAME", "pod-b")
	if got := outboxWorkerID(); got != "pod-b" {
		t.Errorf("outboxWorkerID = %q; want pod-b (hostname fallback)", got)
	}
}

func TestOutboxWorkerID_LocalDefault(t *testing.T) {
	t.Setenv("CHORA_OUTBOX_WORKER_ID", "")
	t.Setenv("HOSTNAME", "")
	if got := outboxWorkerID(); got != "chora-a2a-gateway-local" {
		t.Errorf("outboxWorkerID = %q; want chora-a2a-gateway-local", got)
	}
}

// ----------------------------------------------------------------------------
// bootstrapOutboxDB — env-gated, so only the no-env nil path is unit-testable
// without a live Postgres / Secret Manager back end.
// ----------------------------------------------------------------------------

func TestBootstrapOutboxDB_NoEnvReturnsNil(t *testing.T) {
	t.Setenv("CHORA_OUTBOX_DSN", "")
	t.Setenv("CHORA_OUTBOX_DSN_SECRET_ID", "")
	db, shutdown := bootstrapOutboxDB(context.Background())
	if db != nil {
		t.Errorf("expected nil db when outbox env unset; got %v", db)
	}
	if shutdown != nil {
		t.Errorf("expected nil shutdown when outbox db unwired")
	}
}
