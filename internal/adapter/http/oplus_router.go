// Package httpadapter — OPlusRouter exposes the read-only A2A listing
// endpoints consumed by the O+ surface's A2A Console via the chora-gateway
// BFF (Phase B7 of the O+ hydration plan at
// .claude/plans/atomic-napping-spring.md, ADR-132 §6 A2A Console parity).
//
// Routes:
//
//	GET /api/v1/a2a/contracts                   list all non-deleted contracts
//	GET /api/v1/a2a/identities                  list all non-deleted partner registrations (AGIDs)
//	GET /api/v1/a2a/invocations?since=RFC3339   list invocations (optionally filtered by StartedAt)
//
// CRITICAL: NO routes return or accept a `gcid` field — A2A audit is
// AGID-only (CLAUDE.md §1).
//
// These endpoints back the BFF `GET /bff/oplus/a2a` aggregator (Phase C).
// When chora-a2a-gateway is unreachable, the BFF falls back to the
// `{ mode: 'pending', mock: ... }` response shape (Phase D6).
package httpadapter

import (
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/repo"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/invocation"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/partner"
)

// OPlusConfig is the dependency injection bundle for the O+ listing router.
// Reuses the same in-memory repos that back ExtRouter so the listings
// reflect data written via partner-facing endpoints.
//
// Identities (optional) is the ExternalAgentIdentity store from the legacy
// /a2a/v1/* router. When wired, /api/v1/a2a/identities returns the real
// public-key SHA-256 fingerprint per ADR-132 §3; when nil OR an AGID has
// no registered identity, the field is emitted as an empty string (per
// [[feedback-no-stubs-real-wiring]] — empty/null is honest, sha256(agid)
// would be fabricated).
//
// Now is an optional clock source for deterministic trust-level
// derivation in tests; when nil, time.Now().UTC() is used.
type OPlusConfig struct {
	Registrations repo.RegistrationStore
	Contracts     repo.ContractStore
	Invocations   repo.InvocationStore
	// Identities is env-selected (inmem default | pg durable) by
	// cmd/server/bootstrap.go's chooseIdentityBackend (W0-F1, CHO-2198).
	Identities repo.IdentityStore
	Now        func() time.Time
}

// OPlusRouter is the O+-facing read-only listing router.
type OPlusRouter struct {
	mux *http.ServeMux
	cfg OPlusConfig
}

// NewOPlusRouter constructs the O+ listing router.
func NewOPlusRouter(cfg OPlusConfig) *OPlusRouter {
	r := &OPlusRouter{
		mux: http.NewServeMux(),
		cfg: cfg,
	}
	r.routes()
	return r
}

// ServeHTTP makes OPlusRouter an http.Handler.
func (r *OPlusRouter) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mux.ServeHTTP(w, req)
}

func (r *OPlusRouter) routes() {
	r.mux.HandleFunc("/api/v1/a2a/contracts", r.listContracts)
	r.mux.HandleFunc("/api/v1/a2a/identities", r.listIdentities)
	r.mux.HandleFunc("/api/v1/a2a/invocations", r.listInvocations)
}

// -----------------------------------------------------------------------------
// GET /api/v1/a2a/contracts
// -----------------------------------------------------------------------------

func (r *OPlusRouter) listContracts(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		writeExtError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "use GET")
		return
	}
	if r.cfg.Contracts == nil {
		writeExtJSON(w, http.StatusOK, map[string]any{"contracts": []any{}})
		return
	}
	cs, err := r.cfg.Contracts.ListAll()
	if err != nil {
		writeExtError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}
	out := make([]contractResp, 0, len(cs))
	for _, c := range cs {
		out = append(out, toContractResponse(c))
	}
	writeExtJSON(w, http.StatusOK, map[string]any{"contracts": out})
}

// -----------------------------------------------------------------------------
// GET /api/v1/a2a/identities
//
// Per the O+ A2A Console contract (ADR-132 §6 + audit finding #4) every
// row carries the FE-canonical `trust_level` + `key_fingerprint` derived
// from real backend state. The derivation rule lives on the Registration
// aggregate (`DeriveTrustLevelView`); this handler glues invocations +
// identity store + clock to the aggregate method.
//
// Both fields reflect real signals (no placeholders) per
// [[feedback-no-stubs-real-wiring]]:
//
//   - `trust_level` is one of `verified` / `pilot` / `experimental`,
//     determined by Registration state + DNS-verification + approval age
//     + recent-invocation error rate (see DeriveTrustLevelView).
//
//   - `key_fingerprint` is the SHA-256 hex of the registered Ed25519
//     PEM (computed at registration time in agent_identity.New). When no
//     ExternalAgentIdentity is on file for the AGID (typical for newly
//     approved registrations before the partner uploads their public
//     key), the field is emitted as an EMPTY STRING — never a fabricated
//     fingerprint of the AGID itself.
// -----------------------------------------------------------------------------

func (r *OPlusRouter) listIdentities(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		writeExtError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "use GET")
		return
	}
	if r.cfg.Registrations == nil {
		writeExtJSON(w, http.StatusOK, map[string]any{"identities": []any{}})
		return
	}
	regs, err := r.cfg.Registrations.ListAll()
	if err != nil {
		writeExtError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}
	now := time.Now().UTC()
	if r.cfg.Now != nil {
		now = r.cfg.Now()
	}
	out := make([]map[string]any, 0, len(regs))
	for _, reg := range regs {
		out = append(out, r.registrationToOPlusMap(reg, now))
	}
	writeExtJSON(w, http.StatusOK, map[string]any{"identities": out})
}

// registrationToOPlusMap is the O+ listing projection — extends the
// canonical ExtRouter registrationToMap with the FE-canonical
// `trust_level` + `key_fingerprint` + `rotated_at` fields per audit
// finding #4. Trust + key are derived from REAL backend state.
//
// `rotated_at`: when an ExternalAgentIdentity is on file we surface its
// UpdatedAt (covers initial-registration + later Rotate calls). When no
// identity is on file the field is empty — `created_at` is already
// present in the base map for that signal.
func (r *OPlusRouter) registrationToOPlusMap(reg *partner.Registration, now time.Time) map[string]any {
	m := registrationToMap(reg)

	// trust_level — pull invocations for this partner ID (when an
	// InvocationRepo is configured) and let the domain rule decide.
	var invs []*invocation.Invocation
	if r.cfg.Invocations != nil {
		fetched, err := r.cfg.Invocations.ListByPartner(reg.ID)
		if err == nil {
			invs = fetched
		}
	}
	m["trust_level"] = string(reg.DeriveTrustLevelView(now, invs))

	// key_fingerprint + rotated_at — fetch the ExternalAgentIdentity by
	// AGID. When no identity is on file (e.g. partner approved but has
	// not yet uploaded a key), surface an empty string and an empty
	// rotated_at. Per [[feedback-no-stubs-real-wiring]] an empty value
	// is honest; sha256(agid) would be fabricated and is forbidden.
	keyFingerprint := ""
	rotatedAt := ""
	if r.cfg.Identities != nil && reg.AGID != "" {
		id, err := r.cfg.Identities.Get(reg.AGID)
		switch {
		case err == nil:
			keyFingerprint = id.KeyFingerprint
			rotatedAt = id.UpdatedAt.Format(time.RFC3339)
		case errors.Is(err, repo.ErrNotFound):
			// Expected: no public key uploaded for this AGID yet — emit an
			// empty fingerprint (honest null), never a fabricated sha256(agid).
		default:
			// W0-F1 (CHO-2198): with the durable pg store a lookup CAN fail
			// (DB down / transient). Do NOT silently mask it as "no key" — that
			// would hide an outage behind a legitimate empty-fingerprint state.
			// Log loudly; still emit empty so one row's error doesn't 500 the
			// whole O+ console listing (best-effort read, mirrors r.publish).
			log.Printf("oplus: identity fingerprint lookup failed agid=%s err=%v", reg.AGID, err)
		}
	}
	m["key_fingerprint"] = keyFingerprint
	m["rotated_at"] = rotatedAt
	return m
}

// -----------------------------------------------------------------------------
// GET /api/v1/a2a/invocations?since=RFC3339
// -----------------------------------------------------------------------------

func (r *OPlusRouter) listInvocations(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		writeExtError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "use GET")
		return
	}
	var since time.Time
	if v := req.URL.Query().Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeExtError(w, http.StatusBadRequest, "BAD_SINCE",
				"since must be RFC3339 (e.g. 2026-05-26T00:00:00Z)")
			return
		}
		since = t.UTC()
	}
	if r.cfg.Invocations == nil {
		writeExtJSON(w, http.StatusOK, map[string]any{"invocations": []any{}})
		return
	}
	invs, err := r.cfg.Invocations.ListSince(since)
	if err != nil {
		writeExtError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}
	out := make([]map[string]any, 0, len(invs))
	for _, i := range invs {
		out = append(out, invocationToMap(i))
	}
	writeExtJSON(w, http.StatusOK, map[string]any{"invocations": out})
}
