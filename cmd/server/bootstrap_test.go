// bootstrap_test.go — production wiring helper tests for chora-a2a-gateway.
package main

import (
	"context"
	"errors"
	"testing"
	"time"

	inmemrepo "github.com/apollo-chora/chora-a2a-gateway/internal/adapter/repo/inmem"
	pgrepo "github.com/apollo-chora/chora-a2a-gateway/internal/adapter/repo/pg"
)

func TestBootstrapDBPool_NoEnvReturnsNil(t *testing.T) {
	t.Setenv("CHORA_DB_DSN", "")
	t.Setenv("CHORA_DB_DSN_SECRET_ID", "")
	pool, shutdown := bootstrapDBPool(context.Background())
	if pool != nil {
		t.Fatalf("expected nil pool when DB env unset; got %v", pool)
	}
	if shutdown != nil {
		t.Fatalf("expected nil shutdown when pool unwired")
	}
}

func TestBootstrapBus_NoEnvReturnsNil(t *testing.T) {
	t.Setenv("NATS_URL", "")
	bus, shutdown := bootstrapBus(context.Background())
	if bus != nil {
		t.Fatalf("expected nil bus when NATS_URL unset; got %v", bus)
	}
	if shutdown != nil {
		t.Fatalf("expected nil shutdown when bus unwired")
	}
}

func TestConsumerConfig_Tuning(t *testing.T) {
	t.Parallel()
	cfg := consumerConfig("chora-a2a-gateway.closure-pseudonymise", "chora.a2a.pii.pseudonymise.requested.v1")
	if cfg.Name != "chora-a2a-gateway.closure-pseudonymise" {
		t.Errorf("Name = %q", cfg.Name)
	}
	if cfg.Subject != "chora.a2a.pii.pseudonymise.requested.v1" {
		t.Errorf("Subject = %q", cfg.Subject)
	}
	if cfg.MaxDeliver != 5 {
		t.Errorf("MaxDeliver = %d; want 5", cfg.MaxDeliver)
	}
	if cfg.AckWait != 30*time.Second {
		t.Errorf("AckWait = %v; want 30s", cfg.AckWait)
	}
	wantBackoff := []time.Duration{time.Second, 5 * time.Second, 15 * time.Second, 30 * time.Second}
	if len(cfg.Backoff) != len(wantBackoff) {
		t.Fatalf("Backoff = %v; want %v", cfg.Backoff, wantBackoff)
	}
	for i := range wantBackoff {
		if cfg.Backoff[i] != wantBackoff[i] {
			t.Fatalf("Backoff = %v; want %v", cfg.Backoff, wantBackoff)
		}
	}
	if cfg.DLQSubject != "_dlq.chora.a2a.pii.pseudonymise.requested.v1" {
		t.Errorf("DLQSubject = %q", cfg.DLQSubject)
	}
}

// -----------------------------------------------------------------------------
// selectA2ARepoBackend — durable-by-default repo decision (CHO-2198 twin)
// -----------------------------------------------------------------------------
//
// The chora-a2a-gateway repos (Registration/Contract/Invocation + MCPConfig)
// used to default to volatile in-memory storage when CHORA_A2A_REPO_BACKEND was
// unset — a pod restart dropped the sole sanctioned external cross-project sync
// path. These tests lock durable-by-default: pg whenever the pool is healthy,
// in-memory only as an explicit dev override, fail-loud rather than run on
// volatile memory.

// TestSelectA2ARepoBackend_HealthyPoolUnsetDefaultsToPg is the CHO-2198 twin
// RED: a healthy pool with the env UNSET must select the durable pgx store.
func TestSelectA2ARepoBackend_HealthyPoolUnsetDefaultsToPg(t *testing.T) {
	t.Parallel()

	got, err := selectA2ARepoBackend(true, "")
	if err != nil || got != "pg" {
		t.Fatalf("healthy pool + unset MUST default to durable pg (CHO-2198 twin); got (%q,%v)", got, err)
	}
}

func TestSelectA2ARepoBackend_HealthyPoolExplicitPg(t *testing.T) {
	t.Parallel()

	got, err := selectA2ARepoBackend(true, "pg")
	if err != nil || got != "pg" {
		t.Fatalf("healthy pool + pg: want (pg,nil); got (%q,%v)", got, err)
	}
}

func TestSelectA2ARepoBackend_PgWithoutPoolFailsLoud(t *testing.T) {
	t.Parallel()

	got, err := selectA2ARepoBackend(false, "pg")
	if err == nil {
		t.Fatalf("pg + no pool MUST fail loud; got backend=%q, nil error", got)
	}
	if !errors.Is(err, errA2ARepoPgPoolRequired) {
		t.Errorf("want errA2ARepoPgPoolRequired; got %v", err)
	}
	if got != "" {
		t.Errorf("fail-loud path must not return a backend; got %q", got)
	}
}

func TestSelectA2ARepoBackend_UnsetWithoutPoolFailsLoud(t *testing.T) {
	t.Parallel()

	got, err := selectA2ARepoBackend(false, "")
	if err == nil {
		t.Fatalf("unset + no pool MUST fail loud (no silent volatile storage); got backend=%q, nil error", got)
	}
	if !errors.Is(err, errA2ARepoPgPoolRequired) {
		t.Errorf("want errA2ARepoPgPoolRequired; got %v", err)
	}
}

// TestSelectA2ARepoBackend_ExplicitInmemOverride — the dev escape hatch:
// CHORA_A2A_REPO_BACKEND=inmem (or =memory) selects the volatile store even
// with a healthy pool; the caller emits a loud WARNING. Case-insensitive +
// whitespace-trimmed.
func TestSelectA2ARepoBackend_ExplicitInmemOverride(t *testing.T) {
	t.Parallel()

	for _, env := range []string{"inmem", "INMEM", "memory", " InMem "} {
		env := env
		t.Run(env, func(t *testing.T) {
			t.Parallel()
			got, err := selectA2ARepoBackend(true, env)
			if err != nil || got != "inmem" {
				t.Fatalf("explicit %q must select inmem; got (%q,%v)", env, got, err)
			}
		})
	}
}

func TestSelectA2ARepoBackend_UnknownFailsLoud(t *testing.T) {
	t.Parallel()

	got, err := selectA2ARepoBackend(true, "redis")
	if err == nil {
		t.Fatalf("unknown backend MUST fail loud (no silent selection); got backend=%q, nil error", got)
	}
	if !errors.Is(err, errA2ARepoBackendUnknown) {
		t.Errorf("want errA2ARepoBackendUnknown; got %v", err)
	}
}

// -----------------------------------------------------------------------------
// chooseOPlusRepoBackend / chooseMCPConfigBackend — composition-root wiring
// -----------------------------------------------------------------------------

// TestChooseOPlusRepoBackend_UnsetWithoutPoolFailsLoud — the pre-fix code
// silently defaulted unset → in-memory (the durability anti-pattern this fix
// removes). Now a missing pool with no explicit override is fatal.
func TestChooseOPlusRepoBackend_UnsetWithoutPoolFailsLoud(t *testing.T) {
	t.Setenv("CHORA_A2A_REPO_BACKEND", "")
	got, err := chooseOPlusRepoBackend(nil)
	if err == nil {
		t.Fatalf("unset + nil pool must fail loud (no silent volatile repos); got bundle=%+v, nil error", got)
	}
	if got.Backend != "" || got.Registrations != nil || got.Contracts != nil || got.Invocations != nil {
		t.Fatalf("fail-loud path must not return a repo bundle; got %+v", got)
	}
}

// TestChooseOPlusRepoBackend_PGWithoutPoolFailsLoud locks the fail-loud
// invariant (CLAUDE.md: "never silently fall back"). When `pg` is EXPLICITLY
// requested but the pgx pool is nil (missing/failed DSN), the selector must
// REFUSE — return an error — not silently degrade to non-durable in-memory
// repos. chora-a2a owns the sole sanctioned external cross-project sync path;
// a misconfigured prod deploy must crash-loop loudly, never self-hide data loss.
func TestChooseOPlusRepoBackend_PGWithoutPoolFailsLoud(t *testing.T) {
	t.Setenv("CHORA_A2A_REPO_BACKEND", "pg")
	got, err := chooseOPlusRepoBackend(nil)
	if err == nil {
		t.Fatalf("backend=pg with nil pool must fail loud; got bundle=%+v, nil error", got)
	}
	if got.Backend != "" || got.Registrations != nil || got.Contracts != nil || got.Invocations != nil {
		t.Fatalf("fail-loud path must not return any repo bundle; got %+v", got)
	}
}

func TestChooseOPlusRepoBackend_Inmem(t *testing.T) {
	t.Setenv("CHORA_A2A_REPO_BACKEND", "INMEM")
	got, err := chooseOPlusRepoBackend(nil)
	if err != nil {
		t.Fatalf("explicit inmem override must not error; got %v", err)
	}
	if got.Backend != "inmem" {
		t.Fatalf("backend = %q; want inmem", got.Backend)
	}
	if _, ok := got.Contracts.(*inmemrepo.ContractRepo); !ok {
		t.Errorf("Contracts = %T; want *inmem.ContractRepo", got.Contracts)
	}
}

// TestChooseOPlusRepoBackend_UnknownFailsLoud — a typo'd backend value must not
// silently pick volatile storage (pre-fix it fell back to inmem).
func TestChooseOPlusRepoBackend_UnknownFailsLoud(t *testing.T) {
	t.Setenv("CHORA_A2A_REPO_BACKEND", "redis")
	got, err := chooseOPlusRepoBackend(nil)
	if err == nil {
		t.Fatalf("unrecognised backend must fail loud; got bundle=%+v, nil error", got)
	}
}

// TestChooseMCPConfigBackend_UnsetWithoutPoolFailsLoud — MCPConfig twin of the
// O+ repo durability fix: unset + no pool is fatal, not silent in-memory.
func TestChooseMCPConfigBackend_UnsetWithoutPoolFailsLoud(t *testing.T) {
	t.Setenv("CHORA_A2A_REPO_BACKEND", "")
	got, err := chooseMCPConfigBackend(nil)
	if err == nil {
		t.Fatalf("unset + nil pool must fail loud; got store=%+v, nil error", got)
	}
	if got != nil {
		t.Fatalf("fail-loud path must not return a store; got %+v", got)
	}
}

// TestChooseMCPConfigBackend_PGWithoutPoolFailsLoud mirrors
// TestChooseOPlusRepoBackend_PGWithoutPoolFailsLoud's rationale: pg was
// EXPLICITLY requested but the pgx pool is nil, so the selector must refuse
// rather than silently degrade to a non-durable in-memory MCPConfig store.
func TestChooseMCPConfigBackend_PGWithoutPoolFailsLoud(t *testing.T) {
	t.Setenv("CHORA_A2A_REPO_BACKEND", "pg")
	got, err := chooseMCPConfigBackend(nil)
	if err == nil {
		t.Fatalf("backend=pg with nil pool must fail loud; got store=%+v, nil error", got)
	}
	if got != nil {
		t.Fatalf("fail-loud path must not return a store; got %+v", got)
	}
}

func TestChooseMCPConfigBackend_Inmem(t *testing.T) {
	t.Setenv("CHORA_A2A_REPO_BACKEND", "INMEM")
	got, err := chooseMCPConfigBackend(nil)
	if err != nil {
		t.Fatalf("explicit inmem override must not error; got %v", err)
	}
	if _, ok := got.(*inmemrepo.MCPConfigRepo); !ok {
		t.Errorf("MCPConfigs = %T; want *inmem.MCPConfigRepo", got)
	}
}

// TestChooseMCPConfigBackend_UnknownFailsLoud — typo'd value must fail loud.
func TestChooseMCPConfigBackend_UnknownFailsLoud(t *testing.T) {
	t.Setenv("CHORA_A2A_REPO_BACKEND", "redis")
	got, err := chooseMCPConfigBackend(nil)
	if err == nil {
		t.Fatalf("unrecognised backend must fail loud; got store=%+v, nil error", got)
	}
	if got != nil {
		t.Fatalf("fail-loud path must not return a store; got %+v", got)
	}
}

// Compile-time guard — `pgrepo` import is exercised via the pg branch in
// chooseOPlusRepoBackend / chooseMCPConfigBackend; we silence the
// unused-import lint by referring to the constructors here (the functions
// are the package's public surface).
var (
	_ = pgrepo.NewRegistrationStore
	_ = pgrepo.NewMCPConfigStore
)
