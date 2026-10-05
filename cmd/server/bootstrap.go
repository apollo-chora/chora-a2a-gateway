// bootstrap.go — production wiring helpers for chora-a2a-gateway.
//
// Per `feedback_resilience_priority` + `secrets-and-env`: every production
// dependency is sourced from env vars (env-backed secret resolution in
// production). Local dev sees nil pools / nil bus clients so the server
// keeps the in-memory adapter fallback working.
//
// Environment contract (mirrors chora-identity):
//
//	CHORA_DB_DSN_SECRET_ID  — env-backed secret name resolving to
//	                          chora_a2a DSN (app_rw role).
//	CHORA_DB_DSN            — direct DSN (dev override).
//	CHORA_DB_PROJECT        — project label used for secret resolution.
//	                          Defaults to chora-local.
//	CHORA_DB_REWRITE_FROM_PORT, CHORA_DB_REWRITE_TO_PORT — PgBouncer bypass.
//	NATS_URL                — NATS JetStream broker URL for the event bus.
//
// AGID ≠ GCID (per CLAUDE.md §1 + ddd-enforcement #10) is enforced at the
// domain layer; this file owns infrastructure wiring only.
package main

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	cgcdb "github.com/apollo-chora/chora-common/db"
	"github.com/apollo-chora/chora-common/eventbus"
	cgcsecrets "github.com/apollo-chora/chora-common/secrets"

	legacyinmem "github.com/apollo-chora/chora-a2a-gateway/internal/adapter/inmem"
	a2aoutbox "github.com/apollo-chora/chora-a2a-gateway/internal/adapter/outbox"
	chorapg "github.com/apollo-chora/chora-a2a-gateway/internal/adapter/pg"
	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/repo"
	inmemrepo "github.com/apollo-chora/chora-a2a-gateway/internal/adapter/repo/inmem"
	pgrepo "github.com/apollo-chora/chora-a2a-gateway/internal/adapter/repo/pg"
)

const (
	serviceName = "chora-a2a-gateway"
)

func bootstrapDBPool(ctx context.Context) (*pgxpool.Pool, func()) {
	dsn := os.Getenv("CHORA_DB_DSN")
	secretID := os.Getenv("CHORA_DB_DSN_SECRET_ID")
	if dsn == "" && secretID == "" {
		log.Printf("a2a-gateway: CHORA_DB_DSN / CHORA_DB_DSN_SECRET_ID unset — using in-memory repositories")
		return nil, nil
	}

	project := os.Getenv("CHORA_DB_PROJECT")
	if project == "" {
		project = "chora-local"
	}

	var fetcher cgcdb.SecretFetcher
	var sclient *cgcsecrets.Client
	if secretID != "" && dsn == "" {
		c, err := cgcsecrets.NewClient(ctx, project)
		if err != nil {
			log.Fatalf("a2a-gateway: secret manager init failed (env set, fail-loud): %v", err)
		}
		sclient = c
		fetcher = c
	}

	rewriteFrom, _ := strconv.Atoi(os.Getenv("CHORA_DB_REWRITE_FROM_PORT"))
	rewriteTo, _ := strconv.Atoi(os.Getenv("CHORA_DB_REWRITE_TO_PORT"))

	// Gate-7 fix: env-driven bootstrap context (default 30s). Under
	// concurrent 11-pod cold-start, connection-pooler + secret resolution
	// can exceed 30s. Set CHORA_BOOTSTRAP_TIMEOUT_SECONDS=90 in the
	// deployment env.
	bootstrapSecs, _ := strconv.Atoi(os.Getenv("CHORA_BOOTSTRAP_TIMEOUT_SECONDS"))
	if bootstrapSecs <= 0 {
		bootstrapSecs = 30
	}
	bootstrapCtx, cancel := context.WithTimeout(ctx, time.Duration(bootstrapSecs)*time.Second)
	defer cancel()

	pool, err := cgcdb.Bootstrap(bootstrapCtx, cgcdb.BootstrapOptions{
		DSN:             dsn,
		SecretID:        secretID,
		SecretFetcher:   fetcher,
		RewriteFromPort: rewriteFrom,
		RewriteToPort:   rewriteTo,
		AppName:         serviceName + "@" + version,
		RuntimeParams:   a2aGatewayDBRuntimeParams(),
	})
	if err != nil {
		if sclient != nil {
			_ = sclient.Close()
		}
		log.Fatalf("a2a-gateway: pgx pool bootstrap failed (env set, fail-loud — kubelet will CrashLoopBackOff): %v", err)
	}

	shutdown := func() {
		pool.Close()
		if sclient != nil {
			_ = sclient.Close()
		}
	}
	return pool, shutdown
}

// bootstrapBus returns a NATS JetStream eventbus when NATS_URL is set,
// otherwise nil (the caller falls back to the in-memory bus). The returned
// closure is the shutdown hook; caller defers it.
//
// Environment contract:
//
//	NATS_URL — JetStream broker URL (e.g. nats://127.0.0.1:4222).
//	           Unset → nil bus (in-process fallback; NOT durable).
func bootstrapBus(ctx context.Context) (eventbus.Bus, func()) {
	url := strings.TrimSpace(os.Getenv("NATS_URL"))
	if url == "" {
		return nil, nil
	}
	bus, err := eventbus.NewJetStream(eventbus.JetStreamConfig{URL: url})
	if err != nil {
		log.Printf("a2a-gateway: NATS JetStream init failed: %v — falling back to in-memory bus", err)
		return nil, nil
	}
	return bus, func() { _ = bus.Close() }
}

// consumerConfig is the shared durable-consumer tuning for every
// chora-a2a-gateway subscriber: at-least-once with a 30s ack window, five
// delivery attempts, and the canonical _dlq.<subject> dead-letter routing.
//
// The dotted event bus subscription id is safe as Name — eventbus sanitises it
// to a NATS-legal durable name internally.
func consumerConfig(name, subject string) eventbus.ConsumerConfig {
	return eventbus.ConsumerConfig{
		Name:       name,
		Subject:    subject,
		MaxDeliver: 5,
		AckWait:    30 * time.Second,
		Backoff: []time.Duration{
			1 * time.Second, 5 * time.Second, 15 * time.Second, 30 * time.Second,
		},
		DLQSubject: eventbus.DLQSubject(subject),
	}
}

// -----------------------------------------------------------------------------
// M12.3 W1.5e — per-domain outbox bootstrap helpers (mirror chora-creation
// W1.5a + chora-tenancy W2b). The a2a-gateway per-domain outbox writes to the
// a2a_outbox_events table (migration 0002_outbox.sql).
// -----------------------------------------------------------------------------

func bootstrapOutboxDB(ctx context.Context) (*sql.DB, func()) {
	dsn := os.Getenv("CHORA_OUTBOX_DSN")
	secretID := os.Getenv("CHORA_OUTBOX_DSN_SECRET_ID")
	if dsn == "" && secretID == "" {
		return nil, nil
	}

	var sclient *cgcsecrets.Client
	if dsn == "" {
		project := os.Getenv("CHORA_DB_PROJECT")
		if project == "" {
			project = "chora-local"
		}
		c, err := cgcsecrets.NewClient(ctx, project)
		if err != nil {
			log.Fatalf("a2a-gateway: outbox secret manager init failed (env set, fail-loud): %v", err)
		}
		sclient = c
		bootstrapSecs, _ := strconv.Atoi(os.Getenv("CHORA_BOOTSTRAP_TIMEOUT_SECONDS"))
		if bootstrapSecs <= 0 {
			bootstrapSecs = 30
		}
		resolveCtx, cancel := context.WithTimeout(ctx, time.Duration(bootstrapSecs)*time.Second)
		defer cancel()
		resolved, err := c.GetSecret(resolveCtx, secretID)
		if err != nil {
			_ = c.Close()
			log.Fatalf("a2a-gateway: outbox secret fetch %q failed (env set, fail-loud): %v", secretID, err)
		}
		dsn = resolved
	}

	if rewriteFrom, _ := strconv.Atoi(os.Getenv("CHORA_DB_REWRITE_FROM_PORT")); rewriteFrom != 0 {
		if rewriteTo, _ := strconv.Atoi(os.Getenv("CHORA_DB_REWRITE_TO_PORT")); rewriteTo != 0 {
			rewritten, err := cgcdb.RewriteDSNPort(dsn, rewriteFrom, rewriteTo)
			if err != nil {
				if sclient != nil {
					_ = sclient.Close()
				}
				log.Fatalf("a2a-gateway: outbox DSN port rewrite failed (env set, fail-loud): %v", err)
			}
			dsn = rewritten
		}
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		db, err = sql.Open("postgres", dsn)
	}
	if err != nil {
		if sclient != nil {
			_ = sclient.Close()
		}
		log.Fatalf("a2a-gateway: outbox sql.Open failed (env set, fail-loud): %v", err)
	}
	if pingErr := db.PingContext(ctx); pingErr != nil {
		_ = db.Close()
		if sclient != nil {
			_ = sclient.Close()
		}
		log.Fatalf("a2a-gateway: outbox db.Ping failed (env set, fail-loud): %v", pingErr)
	}
	return db, func() {
		_ = db.Close()
		if sclient != nil {
			_ = sclient.Close()
		}
	}
}

func outboxWorkerID() string {
	if v := os.Getenv("CHORA_OUTBOX_WORKER_ID"); v != "" {
		return v
	}
	if v := os.Getenv("HOSTNAME"); v != "" {
		return v
	}
	return "chora-a2a-gateway-local"
}

// oplusRepoBundle bundles the three repo ports selected by
// `CHORA_A2A_REPO_BACKEND` (env-driven adapter selection per M12 backlog
// + `[[feedback-no-inline-config]]`).
type oplusRepoBundle struct {
	Registrations repo.RegistrationStore
	Contracts     repo.ContractStore
	Invocations   repo.InvocationStore
	Backend       string // "inmem" | "pg"
}

// selectA2ARepoBackend decides the persistence backend ("pg" | "inmem") for
// the chora-a2a-gateway repos (Registration/Contract/Invocation + MCPConfig),
// shared by chooseOPlusRepoBackend + chooseMCPConfigBackend.
//
// Durable-by-default (CHO-2198 twin of the chora-identity passkey fix): a
// healthy chora_a2a pool yields the pgx stores WITHOUT any env opt-in — an
// UNSET CHORA_A2A_REPO_BACKEND used to silently select volatile in-memory
// repos, so a pod restart dropped every A2A registration/contract/invocation.
// In-memory is now available ONLY as an explicit, loudly-announced dev
// override; a missing pool with no override is fatal. chora-a2a owns the sole
// sanctioned external cross-project sync path, so silently degrading to
// volatile storage would be self-hiding data loss.
//
//	envVal (CHORA_A2A_REPO_BACKEND) │ poolHealthy │ result
//	─────────────────────────────────┼─────────────┼──────────────────
//	"" (unset)                       │ true        │ pg (durable)
//	"" (unset)                       │ false       │ error (fail loud)
//	"pg"                             │ true        │ pg (durable)
//	"pg"                             │ false       │ error (fail loud)
//	"inmem" / "memory"               │ any         │ inmem (caller WARNs)
//	anything else                    │ any         │ error (fail loud)
func selectA2ARepoBackend(poolHealthy bool, envVal string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(envVal)) {
	case "inmem", "memory":
		return "inmem", nil
	case "", "pg":
		if poolHealthy {
			return "pg", nil
		}
		return "", errA2ARepoPgPoolRequired
	default:
		return "", errA2ARepoBackendUnknown
	}
}

var (
	errA2ARepoPgPoolRequired = errors.New("chora-a2a-gateway: durable pgx repos required but chora_a2a pool is unavailable — chora-a2a owns the sole sanctioned external cross-project sync path and MUST NOT silently run on volatile memory; set CHORA_A2A_REPO_BACKEND=inmem to explicitly opt into the non-durable dev store")
	errA2ARepoBackendUnknown = errors.New("chora-a2a-gateway: unrecognised CHORA_A2A_REPO_BACKEND (want one of: unset|pg|inmem)")
)

// chooseOPlusRepoBackend selects the persistence backend for the
// Registration / Contract / Invocation aggregates. Durable-by-default via
// selectA2ARepoBackend (pg whenever the pool is healthy; explicit
// CHORA_A2A_REPO_BACKEND=inmem for the dev override).
//
// CHORA_A2A_REPO_TENANT_ID is read for the pg backend to bind list/get
// queries to a tenant per ADR-132 RLS; absent the GUC + bind path the repos
// still query against the row-level policy but defence-in-depth is dropped.
// In production this MUST be set to the request-tenant via the middleware
// that wraps each chora-a2a-gateway request.
func chooseOPlusRepoBackend(pool *pgxpool.Pool) (oplusRepoBundle, error) {
	backend, err := selectA2ARepoBackend(pool != nil, os.Getenv("CHORA_A2A_REPO_BACKEND"))
	if err != nil {
		// Fail-loud: caller log.Fatals → kubelet CrashLoopBackOff rather than
		// run the sole external sync path on volatile storage.
		return oplusRepoBundle{}, err
	}
	if backend == "pg" {
		tenantID := strings.TrimSpace(os.Getenv("CHORA_A2A_REPO_TENANT_ID"))
		q := chorapg.NewPgxPoolQuerier(pool)
		log.Printf("a2a-gateway: O+ repos wired against chora_a2a (backend=pg, tenant_bind=%q)", tenantID)
		return oplusRepoBundle{
			Registrations: pgrepo.NewRegistrationStore(q, tenantID),
			Contracts:     pgrepo.NewContractStore(q, tenantID),
			Invocations:   pgrepo.NewInvocationStore(q, tenantID),
			Backend:       "pg",
		}, nil
	}
	// backend == "inmem" (the only other non-error value).
	log.Printf("WARNING: a2a-gateway: O+ repos wired IN-MEMORY (CHORA_A2A_REPO_BACKEND=inmem) — NOT durable; registrations/contracts/invocations are LOST on restart. Dev/local only; never set this in production.")
	return oplusRepoBundle{
		Registrations: inmemrepo.NewRegistrationRepo(),
		Contracts:     inmemrepo.NewContractRepo(),
		Invocations:   inmemrepo.NewInvocationRepo(),
		Backend:       "inmem",
	}, nil
}

// chooseMCPConfigBackend selects the persistence backend for the per-tenant
// MCP-as-a-Service add-on config, using the SAME CHORA_A2A_REPO_BACKEND
// switch as chooseOPlusRepoBackend above. It is kept separate from
// oplusRepoBundle because MCPConfigStore is NOT bound to a single tenant at
// construction the way Registrations/Contracts/Invocations are — Put/Get/
// SetSuspended all take tenant_id per call, and ByAPIKeyHash is an
// inherently pre-tenant reverse lookup (see
// internal/adapter/repo/pg/mcpconfig.go's doc comment for the full
// rationale, including why that lookup is deliberately not RLS-bypass).
//
// Durable-by-default via selectA2ARepoBackend (CHO-2198 twin):
//   - unset / pg + healthy pool → Postgres chora_a2a (durable).
//   - CHORA_A2A_REPO_BACKEND=inmem → in-memory adapter (keys wiped on restart;
//     explicit dev override, announced with a loud WARNING).
//   - pg/unset without a pool → fail loud (never silently volatile).
func chooseMCPConfigBackend(pool *pgxpool.Pool) (repo.MCPConfigStore, error) {
	backend, err := selectA2ARepoBackend(pool != nil, os.Getenv("CHORA_A2A_REPO_BACKEND"))
	if err != nil {
		return nil, err
	}
	if backend == "pg" {
		q := chorapg.NewPgxPoolQuerier(pool)
		log.Printf("a2a-gateway: MCPConfig repo wired against chora_a2a (backend=pg)")
		return pgrepo.NewMCPConfigStore(q), nil
	}
	// backend == "inmem" (the only other non-error value).
	log.Printf("WARNING: a2a-gateway: MCPConfig repo wired IN-MEMORY (CHORA_A2A_REPO_BACKEND=inmem) — NOT durable; MCP API keys are LOST on restart. Dev/local only; never set this in production.")
	return inmemrepo.NewMCPConfigRepo(), nil
}

// chooseBYOAKeyBackend selects the persistence backend for the BYOA
// external-LLM key vault (partner API-key hashes — AUTH state), using the SAME
// CHORA_A2A_REPO_BACKEND switch as chooseMCPConfigBackend. W0-F1 (CHO-2198)
// closes the "BYOA keys wiped on restart" durability gap. Keyed BY (tenant,
// provider) per call, so — like MCPConfigStore — no tenant is bound at
// construction.
//
//   - CHORA_A2A_REPO_BACKEND=inmem (default) → in-memory adapter (keys wiped on
//     restart — the pre-existing gap this closes for pg).
//   - CHORA_A2A_REPO_BACKEND=pg → Postgres chora_a2a (requires `pool`).
func chooseBYOAKeyBackend(pool *pgxpool.Pool) (repo.BYOAKeyStore, error) {
	backend := strings.ToLower(strings.TrimSpace(os.Getenv("CHORA_A2A_REPO_BACKEND")))
	if backend == "" {
		backend = "inmem"
	}
	switch backend {
	case "pg":
		if pool == nil {
			// Fail-loud, matching chooseMCPConfigBackend: pg was EXPLICITLY
			// requested but the pool is unwired. Refuse to boot rather than
			// silently drop back to a non-durable BYOA key vault (AUTH state).
			return nil, errors.New(
				"CHORA_A2A_REPO_BACKEND=pg requested but pgx pool unwired " +
					"(check CHORA_DB_DSN / CHORA_DB_DSN_SECRET_ID); refusing to " +
					"fall back to a non-durable in-memory BYOA key store")
		}
		q := chorapg.NewPgxPoolQuerier(pool)
		log.Printf("a2a-gateway: BYOA key repo wired against chora_a2a (backend=pg)")
		return pgrepo.NewBYOAKeyStore(q), nil
	case "inmem":
		log.Printf("a2a-gateway: BYOA key repo wired in-memory (backend=inmem)")
		return inmemrepo.NewBYOAKeyRepo(), nil
	default:
		log.Printf("a2a-gateway: CHORA_A2A_REPO_BACKEND=%q unrecognised — BYOA key repo falling back to inmem", backend)
		return inmemrepo.NewBYOAKeyRepo(), nil
	}
}

// chooseIdentityBackend selects the persistence backend for the
// ExternalAgentIdentity store (partner public-key PEM + SHA-256 fingerprint the
// O+ A2A console reads), using the SAME CHORA_A2A_REPO_BACKEND switch. W0-F1
// (CHO-2198) closes the "agent public keys wiped on restart" durability gap.
// tenantID is bound at construction from CHORA_A2A_REPO_TENANT_ID (the SAME env
// var chooseOPlusRepoBackend uses), mirroring RegistrationStore.
//
//   - CHORA_A2A_REPO_BACKEND=inmem (default) → in-memory adapter (keys wiped on
//     restart — the pre-existing gap this closes for pg).
//   - CHORA_A2A_REPO_BACKEND=pg → Postgres chora_a2a (requires `pool`).
func chooseIdentityBackend(pool *pgxpool.Pool) (repo.IdentityStore, error) {
	backend := strings.ToLower(strings.TrimSpace(os.Getenv("CHORA_A2A_REPO_BACKEND")))
	if backend == "" {
		backend = "inmem"
	}
	switch backend {
	case "pg":
		if pool == nil {
			return nil, errors.New(
				"CHORA_A2A_REPO_BACKEND=pg requested but pgx pool unwired " +
					"(check CHORA_DB_DSN / CHORA_DB_DSN_SECRET_ID); refusing to " +
					"fall back to a non-durable in-memory identity store")
		}
		tenantID := strings.TrimSpace(os.Getenv("CHORA_A2A_REPO_TENANT_ID"))
		q := chorapg.NewPgxPoolQuerier(pool)
		log.Printf("a2a-gateway: identity store wired against chora_a2a (backend=pg, tenant_bind=%q)", tenantID)
		return pgrepo.NewIdentityStore(q, tenantID), nil
	case "inmem":
		log.Printf("a2a-gateway: identity store wired in-memory (backend=inmem)")
		return legacyinmem.NewIdentityStore(), nil
	default:
		log.Printf("a2a-gateway: CHORA_A2A_REPO_BACKEND=%q unrecognised — identity store falling back to inmem", backend)
		return legacyinmem.NewIdentityStore(), nil
	}
}

type sqlDBAdapter struct {
	db *sql.DB
}

func (a sqlDBAdapter) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return a.db.ExecContext(ctx, query, args...)
}

func (a sqlDBAdapter) QueryContext(ctx context.Context, query string, args ...any) (a2aoutbox.SQLRows, error) {
	return a.db.QueryContext(ctx, query, args...)
}

var _ a2aoutbox.SQLDB = sqlDBAdapter{}

// a2aGatewayDBRuntimeParams returns the per-connection Postgres GUCs that keep a
// DB write from hanging forever (fail-loud). Platform-wide rollout of the
// CHO-2005 fix (2026-07-04); mirrors chora-consumption's
// consumptionDBRuntimeParams. Set on every pooled connection via
// BootstrapOptions.RuntimeParams.
//
//   - lock_timeout=3s: a statement blocked on a row lock ERRORs ("canceling
//     statement due to lock timeout") instead of waiting indefinitely and
//     leaking the request goroutine — under the gateway's 6s per-call
//     timeout, so this service fails loud (500) before the gateway 504s.
//   - idle_in_transaction_session_timeout=60s: reaps a leaked open
//     transaction so its row locks release.
//
// No statement_timeout (owner steer): long read paths must not be capped.
func a2aGatewayDBRuntimeParams() map[string]string {
	return map[string]string{
		"lock_timeout":                        "3s",
		"idle_in_transaction_session_timeout": "60s",
	}
}
