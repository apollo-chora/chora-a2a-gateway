// Package main is the chora-a2a-gateway standalone entrypoint.
//
// Per ADR-132 §8 + Tier 1 Post-Review Addendum #1 the service receives
// external Agent-to-Agent traffic via the a2a.chora.site ingress →
// chora-a2a-gateway.
//
// Wiring:
//   - REST: legacy internal /a2a/v1/* router (Router)
//   - REST: partner-facing /partners /admin/* /contracts /a2a/invoke /a2a/audit
//     /admin/byoa /admin/mcp /admin/dns/verify (ExtRouter)
//   - gRPC: A2AInvokerService (called by Chora-side services to invoke
//     external agents on behalf of a learner). M12 wires Protobuf stubs;
//     for now the InvokerServer exposes a Go-level API only.
//   - Closure subscriber: AGID-target chora.closure.requested.v1 events
//
// This is the standalone, cloud-neutral build: PostgreSQL repositories, a
// NATS JetStream event bus, OTLP tracing via OTEL_EXPORTER_OTLP_ENDPOINT,
// and env-backed configuration. The former Google Cloud dependencies
// (the service, the platform ingress, the event bus, the OTLP endpoint, Secret
// Manager) have been removed.
//
// Per CLAUDE.md §6 (no inline config) all URLs/secrets/adapter configs
// come from env vars. The skeleton uses sensible localhost defaults for
// the in-memory adapters so unit tests can exercise the full HTTP
// surface.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/apollo-chora/chora-common/durabilityguard"
	"github.com/apollo-chora/chora-common/eventbus"
	// pgx stdlib driver — registered for sql.Open("pgx", dsn) used by
	// the per-domain outbox PostgresStore in bootstrap.go.
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/closure"
	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/dns"
	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/events"
	grpcadapter "github.com/apollo-chora/chora-a2a-gateway/internal/adapter/grpc"
	httpadapter "github.com/apollo-chora/chora-a2a-gateway/internal/adapter/http"
	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/inmem"
	a2aoutbox "github.com/apollo-chora/chora-a2a-gateway/internal/adapter/outbox"
	chorapg "github.com/apollo-chora/chora-a2a-gateway/internal/adapter/pg"
	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/rate_limiter"
	"github.com/apollo-chora/chora-a2a-gateway/internal/observability"
)

const (
	defaultPort = "8080"
	version     = "0.2.0"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = defaultPort
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// OTLP wiring per Tier 3 D13 — direct to the configured OTLP endpoint
	// (OTel Collector in prod, stdout in dev).
	//
	// Per C(a).S1 path (b) — tracker #151 — OTLP init runs in its own
	// goroutine with its own (env-tunable, default 15s) deadline + fail-
	// soft semantics. Timeout / init-error degrade to a no-op shutdown,
	// so the rest of bootstrap (pgx pool, event bus) gets the FULL
	// CHORA_BOOTSTRAP_TIMEOUT_SECONDS budget.
	otlpHandle := observability.InitAsync(ctx)
	defer func() {
		// WaitContext blocks until init settles — usually a no-op by
		// shutdown time because pgx-pool init below already gave OTLP
		// best-effort wall-clock to land.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		res := otlpHandle.WaitContext(shutdownCtx)
		if err := res.Shutdown(shutdownCtx); err != nil {
			log.Printf("trace shutdown error: %v", err)
		}
	}()

	// -----------------------------------------------------------------------
	// Service wiring: optional pgx pool + NATS JetStream event bus. Empty
	// env keeps the in-memory adapter fallback below; set CHORA_DB_DSN +
	// NATS_URL in production.
	// -----------------------------------------------------------------------
	pool, poolShutdown := bootstrapDBPool(ctx)
	if poolShutdown != nil {
		defer poolShutdown()
	}
	jetBus, busShutdown := bootstrapBus(ctx)
	if busShutdown != nil {
		defer busShutdown()
	}
	if pool != nil {
		log.Printf("a2a-gateway: pgx pool wired (db=chora_a2a) — partner repo available")
	}
	if jetBus != nil {
		log.Printf("a2a-gateway: NATS JetStream event bus wired (url=%s)", os.Getenv("NATS_URL"))
	}
	_ = pool // partner pgx repo lives in internal/adapter/pg; ExtRouter wires in M14

	// Federated closure-saga subscriber (CHO-1719 / Tier 3 D11): consumes
	// chora.a2a.pii.pseudonymise.requested.v1, applies the per-domain
	// PII_Closure_Map.yaml duty, and acks on
	// chora.a2a.account.pseudonymised.v1.
	//
	// Repo seam (CHO-2198, W0-F1 durability + W0-F5 error-honesty): pg on a
	// healthy pool (durable ack/dedup — migration 0008,
	// closure_pseudonymisation_state), in-memory ONLY when the pool is
	// absent, mirroring the chora-payments else-branch shape. Before this
	// fix the repo was UNGATED — gated on the bus client only, never on
	// pool health — so the ack/dedup state was lost on every pod restart
	// even with a healthy chora_a2a pool (see
	// docs/references/w0-f1-inmemory-inventory.md §6 item 4). Real
	// per-table pg tokenisation (actually redacting a2a_contracts /
	// byoa_credentials / ... columns) remains separate, deeper M12+ debt —
	// this fix is durability of the ack/dedup SIGNAL only, not the
	// redaction itself. Pull subscription is provisioned by infra; override
	// the name via env.
	//
	// closureRepo is hoisted to function scope so the ADR-236 D5 durability
	// guard (below, after the O+ repos are wired) can classify it alongside
	// the other repos. It stays nil when the bus is absent (or the PII map
	// fails to load) — the guard reports nil as UNKNOWN, never a violation.
	// Mirrors the chora-tenancy / chora-observability D5 closureRepo hoist.
	var closureRepo events.ClosureRepository
	if jetBus != nil {
		piiPath := os.Getenv("CHORA_PII_CLOSURE_MAP_PATH")
		if piiPath == "" {
			piiPath = "config/PII_Closure_Map.yaml"
		}
		closureAckPub := events.NewBusClosureAckPublisher(jetBus, events.SourceProject, "chora-a2a-gateway")
		if pool != nil {
			closureRepo = chorapg.NewClosureRepository(chorapg.NewPgxPoolQuerier(pool))
			log.Printf("a2a-gateway: pg ClosureRepository wired (table=closure_pseudonymisation_state)")
		} else {
			closureRepo = events.NewInMemoryClosureRepo()
			log.Printf("a2a-gateway: CHORA_DB_DSN unset — closure repo uses in-memory store (NOT durable across restart)")
		}
		if closureSub, err := events.BootstrapClosureSubscriber(piiPath, closureRepo, closureAckPub, nil); err != nil {
			log.Printf("a2a-gateway: closure subscriber DISABLED (PII map load: %v)", err)
		} else {
			closureSubName := os.Getenv("CHORA_CLOSURE_SUBSCRIPTION")
			if closureSubName == "" {
				closureSubName = "chora-a2a-gateway.closure-pseudonymise"
			}
			go func() {
				log.Printf("a2a-gateway: closure subscriber binding %s -> %s", closureSubName, events.TopicPseudonymiseRequested)
				if err := jetBus.Subscribe(ctx, consumerConfig(closureSubName, events.TopicPseudonymiseRequested), events.ClosurePullHandler(closureSub)); err != nil && !errors.Is(err, context.Canceled) {
					log.Printf("a2a-gateway: closure subscriber exited: %v", err)
				}
			}()
		}
	}

	// -----------------------------------------------------------------------
	// Adapter wiring — in-memory only for the skeleton. M12 swaps for
	// Postgres repos (chora_a2a database) + the token-bucket rate limiter
	// backend + the event-bus publisher.
	// -----------------------------------------------------------------------

	// Legacy /a2a/v1/* router state (kept for backwards-compat with the
	// session-per-call API the early M11 skeleton exposed).
	partners := inmem.NewPartnerStore()
	sessions := inmem.NewSessionStore()
	limiter := inmem.NewRateLimiter()

	// ExternalAgentIdentity store — env-selected inmem (default) | pg durable
	// (W0-F1, CHO-2198). Holds the partner public-key PEM + SHA-256 fingerprint
	// the O+ A2A console reads; the pg backend persists it to chora_a2a so a
	// pod restart no longer wipes it. Fail-loud when pg is requested without a
	// pool (chooseIdentityBackend).
	identity, err := chooseIdentityBackend(pool)
	if err != nil {
		log.Fatalf("a2a-gateway: identity store backend selection failed (env set, fail-loud — kubelet will CrashLoopBackOff): %v", err)
	}

	// Partner-facing ExtRouter state. The three O+ aggregate repos
	// (Registration / Contract / Invocation) are env-selected per
	// CHORA_A2A_REPO_BACKEND = inmem (default) | pg (M12 backlog cleared).
	// MCPConfig, BYOA keys, and the ExternalAgentIdentity store now follow the
	// SAME switch (W0-F1 pg-durability, CHO-2198 — see cmd/server/bootstrap.go's
	// chooseMCPConfigBackend / chooseBYOAKeyBackend / chooseIdentityBackend).
	oplusRepos, err := chooseOPlusRepoBackend(pool)
	if err != nil {
		log.Fatalf("a2a-gateway: O+ repo backend selection failed (env set, fail-loud — kubelet will CrashLoopBackOff): %v", err)
	}
	regs := oplusRepos.Registrations
	contracts := oplusRepos.Contracts
	invocations := oplusRepos.Invocations
	byoaKeys, err := chooseBYOAKeyBackend(pool)
	if err != nil {
		log.Fatalf("a2a-gateway: BYOA key repo backend selection failed (env set, fail-loud — kubelet will CrashLoopBackOff): %v", err)
	}
	mcpConfigs, err := chooseMCPConfigBackend(pool)
	if err != nil {
		log.Fatalf("a2a-gateway: MCPConfig repo backend selection failed (env set, fail-loud — kubelet will CrashLoopBackOff): %v", err)
	}

	// ADR-236 D5 — report-only runtime durability guard over the composition
	// root (W0-F1 gate, CHO-2198). Classifies each wired repo by SHAPE (holds a
	// live *pgxpool.Pool ⇒ DURABLE; a data map ⇒ IN_MEMORY). Report-only unless
	// CHORA_DURABILITY_GUARD=enforce with an owner-signed allow-list (nil here),
	// so the always-in-memory sites surface as VIOLATION rather than being
	// silently accepted. registrations/contracts/invocations/mcp_configs +
	// byoa_keys + identities are now durable-by-default (chooseOPlusRepoBackend /
	// chooseMCPConfigBackend / chooseBYOAKeyBackend / chooseIdentityBackend all
	// return pg on a healthy chora_a2a pool) — W0-F1 (CHO-2198) closed the AUTH-
	// state gap: byoa_keys holds partner API-key hashes and identities holds the
	// O+ public-key fingerprints. Remaining M12 in-memory backlog = the legacy
	// /a2a/v1/* partner + session stores only. closure is pg-or-nil (hoisted
	// above) and reports DURABLE on a healthy pool, UNKNOWN when the bus/pool is
	// absent.
	durabilityguard.Guard("chora-a2a-gateway", []durabilityguard.Binding{
		{Port: "registrations", Adapter: regs},
		{Port: "contracts", Adapter: contracts},
		{Port: "invocations", Adapter: invocations},
		{Port: "mcp_configs", Adapter: mcpConfigs},
		{Port: "byoa_keys", Adapter: byoaKeys},
		{Port: "legacy_partners", Adapter: partners},
		{Port: "legacy_sessions", Adapter: sessions},
		{Port: "identities", Adapter: identity},
		{Port: "closure", Adapter: closureRepo},
	}, nil)

	// ----------------------------------------------------------------------
	// D6.2 producer-side outbox wiring (M12.3 W1e + W1.5e bootstrap).
	//
	// Per `feedback_d6_resilience_first_class` + `agentic-resilience-d6`
	// skill Pillar 2. The per-domain Publisher satisfies events.Publisher
	// by writing every Publish call to a2a_outbox_events; the Dispatcher
	// drains to the NATS JetStream event bus on a background goroutine.
	//
	// Fallback ladder (same as chora-creation W1.5a):
	//   1. pool nil                   → events.InMemoryPublisher (dev)
	//   2. pool set + outboxDB nil    → outbox.InMemoryStore (dev w/ pool)
	//   3. pool set + outboxDB set    → outbox.PostgresStore (prod)
	// ----------------------------------------------------------------------
	var publisher events.Publisher = events.NewInMemoryPublisher()
	var outboxStore a2aoutbox.Store
	var outboxDispatcher *a2aoutbox.Dispatcher
	var dispatcherDone chan struct{}

	outboxDB, outboxDBShutdown := bootstrapOutboxDB(ctx)
	if outboxDBShutdown != nil {
		defer outboxDBShutdown()
	}

	// Event bus: NATS JetStream when NATS_URL is wired, in-memory otherwise.
	// The outbox dispatcher takes the Publisher view of whichever is wired;
	// the closure subscriber above binds to the full JetStream bus.
	var outboxBus a2aoutbox.Bus = eventbus.NewInMemoryBus()
	if jetBus != nil {
		outboxBus = jetBus
	} else {
		log.Printf("a2a-gateway: in-memory event bus wired (NATS_URL unset; NOT durable across restart)")
	}

	if pool != nil {
		if outboxDB != nil {
			outboxStore = a2aoutbox.NewPostgresStore(
				sqlDBAdapter{db: outboxDB},
				a2aoutbox.PostgresStoreOptions{WorkerID: outboxWorkerID()},
			)
			log.Printf("a2a-gateway: outbox PostgresStore wired (worker_id=%s)", outboxWorkerID())
		} else {
			outboxStore = a2aoutbox.NewInMemoryStore()
			log.Printf("a2a-gateway: outbox InMemoryStore wired (CHORA_OUTBOX_DSN unset; NOT durable across restart)")
		}
		// SourceProject must be passed explicitly. NewPublisher defaults it to
		// the chora-local literal, and that default is what every production
		// event was stamped with: the manifest sets CHORA_SOURCE_PROJECT and
		// the overlay rewrites it per environment, but nothing on this path
		// read it. events.SourceProject is the env-derived value (CHO-2419),
		// previously reachable only from the dev-mode in-memory publisher.
		// The fallback stays, so this estate is provably unchanged.
		publisher = a2aoutbox.NewPublisher(a2aoutbox.PublisherConfig{
			Store:         outboxStore,
			SourceProject: events.SourceProject,
		})

		outboxDispatcher = a2aoutbox.NewDispatcher(a2aoutbox.DispatcherConfig{
			Store:    outboxStore,
			Bus:      outboxBus,
			WorkerID: outboxWorkerID(),
		})
		dispatcherDone = make(chan struct{})
		go func() {
			defer close(dispatcherDone)
			if err := outboxDispatcher.Run(ctx, 100); err != nil &&
				!errors.Is(err, context.Canceled) &&
				!errors.Is(err, context.DeadlineExceeded) {
				log.Printf("a2a-gateway: outbox dispatcher exited: %v", err)
			}
		}()
		log.Printf("a2a-gateway: outbox dispatcher goroutine started (batch=100)")
	}
	rl := rate_limiter.NewTokenBucket()
	dnsResolver := dns.NewGoLookupResolver()

	// Closure subscriber wires to the same registrations + publisher.
	// nil inbox triggers the defensive MemoryStore fallback in
	// NewSubscriber. When the M10 event-bus Receive loop lands, swap this
	// for idempotent.PostgresStore against chora_a2a idempotency_keys.
	_ = closure.NewSubscriber(regs, publisher, nil) // event-bus subscriber wiring lands in M12.

	// gRPC handler shares all five repos with the REST adapter.
	_ = grpcadapter.NewHandler(grpcadapter.HandlerConfig{
		Registrations: regs,
		Contracts:     contracts,
		Invocations:   invocations,
		Publisher:     publisher,
		RateLimiter:   rl,
	})

	// -----------------------------------------------------------------------
	// HTTP routers
	// -----------------------------------------------------------------------

	legacyRouter := httpadapter.NewRouter(partners, sessions, identity, limiter)

	extRouter := httpadapter.NewExtRouter(httpadapter.ExtConfig{
		Registrations: regs,
		Contracts:     contracts,
		Invocations:   invocations,
		BYOAKeys:      byoaKeys,
		MCPConfigs:    mcpConfigs,
		Publisher:     publisher,
		RateLimiter:   rl,
		DNSResolver:   dnsResolver,
	})

	// OPlusRouter exposes read-only /api/v1/a2a/* listings consumed by the
	// chora-gateway BFF (`GET /bff/oplus/a2a`) backing the O+ A2A Console
	// (Phase B7 of the O+ hydration plan).
	//
	// Identities is wired so the listing emits the REAL public-key
	// SHA-256 fingerprint per ADR-132 §3; when an AGID has no
	// ExternalAgentIdentity on file (typical pre-key-upload) the field is
	// emitted empty rather than fabricated.
	oplusRouter := httpadapter.NewOPlusRouter(httpadapter.OPlusConfig{
		Registrations: regs,
		Contracts:     contracts,
		Invocations:   invocations,
		Identities:    identity,
	})

	// -----------------------------------------------------------------------
	// Compose: prefer extRouter for the partner-facing routes, fall through
	// to legacyRouter for /a2a/v1/* + /healthz + /readyz.
	// -----------------------------------------------------------------------
	mux := http.NewServeMux()
	// O+ listing routes (BFF-facing). Mounted before ExtRouter so the more
	// specific /api/v1/a2a/* prefix wins.
	mux.Handle("/api/v1/a2a/contracts", oplusRouter)
	mux.Handle("/api/v1/a2a/identities", oplusRouter)
	mux.Handle("/api/v1/a2a/invocations", oplusRouter)
	// ExtRouter prefixes (partner-facing) — handled first.
	for _, prefix := range []string{
		"/partners/", "/partners/register",
		"/admin/partners", "/admin/partners/",
		"/contracts/",
		"/a2a/invoke", "/a2a/audit",
		"/admin/byoa/", "/admin/mcp/", "/admin/dns/",
	} {
		mux.Handle(prefix, extRouter)
	}
	// Legacy v1 + health.
	mux.Handle("/a2a/v1/", legacyRouter)
	mux.Handle("/healthz", legacyRouter)
	mux.Handle("/healthz/", legacyRouter)
	mux.Handle("/health", legacyRouter)
	mux.Handle("/readyz", legacyRouter)

	// OTLP traceparent middleware.
	handler := observability.MiddlewareTraceparent(mux)

	addr := ":" + port
	log.Printf("service=%s version=%s listening on %s",
		observability.ServiceName, version, addr)

	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	<-ctx.Done()
	log.Printf("shutting down...")

	drainCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(drainCtx); err != nil {
		log.Printf("server shutdown error: %v", err)
	}

	// Final outbox drain — flush in-flight pending rows before exit.
	if outboxDispatcher != nil {
		finalDrain, fcancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer fcancel()
		if n, derr := outboxDispatcher.DrainOnce(finalDrain, 200); derr != nil {
			log.Printf("a2a-gateway: final outbox drain error: %v (drained %d)", derr, n)
		} else {
			log.Printf("a2a-gateway: final outbox drain published %d rows", n)
		}
	}
	if dispatcherDone != nil {
		select {
		case <-dispatcherDone:
		case <-time.After(5 * time.Second):
			log.Printf("a2a-gateway: outbox dispatcher shutdown timed out (5s)")
		}
	}
}
