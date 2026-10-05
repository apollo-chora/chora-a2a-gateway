// Package httpadapter wires the chora-a2a-gateway REST endpoints per the
// user task spec for the M11 skeleton:
//
//	GET  /healthz                                → liveness
//	GET  /readyz                                 → readiness
//	POST /a2a/v1/invoke                          → primary entry; X-AGID required
//	GET  /a2a/v1/partners/{agid}                 → fetch partner registry entry
//	POST /a2a/v1/partners                        → register partner (admin placeholder)
//	GET  /a2a/v1/sessions/{correlation_id}       → fetch session log
//
// Real impl in M12 will:
//   - dispatch /invoke to internal Chora-side agents per ADR-132 §8
//   - publish chora.a2a.invocation.* events to event bus Schema Registry
//   - replace the JWT decode-only with full Identity Platform verification
//
// Note on contract divergence: the user-task endpoints (/a2a/v1/invoke,
// /a2a/v1/partners, /a2a/v1/sessions) differ from the OpenAPI in
// chora-contracts/openapi/a2a-gateway.yaml (which defines /a2a/contracts,
// /a2a/invocations, /a2a/external-agents, /a2a/handshake). The skeleton
// follows the user spec verbatim; AP-01 reconciliation happens at M11.4.
package httpadapter

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/inmem"
	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/repo"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/partner"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/session"
)

// -----------------------------------------------------------------------------
// Router
// -----------------------------------------------------------------------------

// Router wires the REST endpoints. Implements http.Handler.
type Router struct {
	mux      *http.ServeMux
	partners *inmem.PartnerStore
	sessions *inmem.SessionStore
	// identity is env-selected (inmem default | pg durable) behind the
	// repo.IdentityStore port (W0-F1, CHO-2198). The legacy /a2a/v1/* router
	// holds it for parity but does not currently read it (the O+ console does).
	identity repo.IdentityStore
	limiter  *inmem.RateLimiter
}

// NewRouter constructs the gateway HTTP router.
func NewRouter(
	partners *inmem.PartnerStore,
	sessions *inmem.SessionStore,
	identity repo.IdentityStore,
	limiter *inmem.RateLimiter,
) *Router {
	r := &Router{
		mux:      http.NewServeMux(),
		partners: partners,
		sessions: sessions,
		identity: identity,
		limiter:  limiter,
	}
	r.routes()
	return r
}

// ServeHTTP makes Router an http.Handler.
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mux.ServeHTTP(w, req)
}

func (r *Router) routes() {
	// /healthz NOTE: Google Front End on the service intercepts the EXACT
	// bare path /healthz before requests reach the container, returning
	// a Google 404 HTML page (same gotcha as chora-aplus-api-hello).
	// We register /health, /healthz, /healthz/ — clients should prefer
	// /readyz or /health on the service *.run.app URLs. Once GCLB+Cloud
	// Armor fronts the gateway (post-M10), /healthz works normally.
	r.mux.HandleFunc("/health", r.healthz)
	r.mux.HandleFunc("/healthz", r.healthz)
	r.mux.HandleFunc("/healthz/", r.healthz)
	r.mux.HandleFunc("/readyz", r.readyz)

	// /a2a/v1/* — exact + prefix paths. ServeMux routes the longest
	// match; we use a single dispatcher to inspect the path components.
	r.mux.HandleFunc("/a2a/v1/invoke", r.invoke)
	r.mux.HandleFunc("/a2a/v1/partners", r.partnersCollection)
	r.mux.HandleFunc("/a2a/v1/partners/", r.partnersByAGID)
	r.mux.HandleFunc("/a2a/v1/sessions/", r.sessionsByCorrelation)
}

// -----------------------------------------------------------------------------
// Health / readiness (no X-AGID required)
// -----------------------------------------------------------------------------

type healthResp struct {
	Status  string `json:"status"`
	Service string `json:"service"`
	Time    string `json:"time"`
}

func (r *Router) healthz(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "use GET")
		return
	}
	writeJSON(w, http.StatusOK, healthResp{
		Status: "ok", Service: "chora-a2a-gateway", Time: time.Now().UTC().Format(time.RFC3339),
	})
}

func (r *Router) readyz(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "use GET")
		return
	}
	writeJSON(w, http.StatusOK, healthResp{
		Status: "ready", Service: "chora-a2a-gateway", Time: time.Now().UTC().Format(time.RFC3339),
	})
}

// -----------------------------------------------------------------------------
// /a2a/v1/invoke
// -----------------------------------------------------------------------------

type invokeRequest struct {
	Action string         `json:"action"`
	Params map[string]any `json:"params"`
}

// invokeResponse intentionally has NO gcid field — A2A is AGID-only.
// CLAUDE.md §1: AGID is distinct from GCID.
type invokeResponse struct {
	CorrelationID string         `json:"correlation_id"`
	AGID          string         `json:"agid"`
	Action        string         `json:"action"`
	Status        string         `json:"status"`
	RoutedTo      string         `json:"routed_to"`
	Echo          map[string]any `json:"echo"`
}

func (r *Router) invoke(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "use POST")
		return
	}
	agid := req.Header.Get("X-AGID")
	if agid == "" {
		writeError(w, http.StatusBadRequest, "MISSING_AGID", "X-AGID header required on /a2a/v1/* endpoints")
		return
	}
	corr := req.Header.Get("X-Correlation-Id")
	if corr == "" {
		writeError(w, http.StatusBadRequest, "MISSING_CORRELATION_ID", "X-Correlation-Id header required")
		return
	}

	// JWT decode (signature verification deferred to M14).
	auth := req.Header.Get("Authorization")
	if jwtSub, err := decodeJWTSubject(auth); err == nil {
		log.Printf("agid=%s correlation_id=%s jwt_sub=%s action=invoke (signature unverified — M14 work)",
			agid, corr, jwtSub)
	} else {
		log.Printf("agid=%s correlation_id=%s jwt_decode_err=%v action=invoke", agid, corr, err)
	}

	// Look up partner.
	p, err := r.partners.Get(agid)
	if errors.Is(err, inmem.ErrNotFound) {
		writeError(w, http.StatusNotFound, "PARTNER_NOT_FOUND", "no partner registered for agid")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}
	if !p.IsActive() {
		writeError(w, http.StatusForbidden, "PARTNER_SUSPENDED",
			"partner is suspended or soft-deleted; reason="+p.SuspendReason)
		return
	}

	// Rate limit.
	if !r.limiter.Allow(agid) {
		writeError(w, http.StatusTooManyRequests, "RATE_LIMITED",
			"per-AGID rate limit exceeded; see partner.rate_limit_per_minute")
		return
	}

	// Parse body.
	var body invokeRequest
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_BODY", "request body is not valid JSON")
		return
	}
	if strings.TrimSpace(body.Action) == "" {
		writeError(w, http.StatusBadRequest, "MISSING_ACTION", "request body.action is required")
		return
	}

	// Append session (append-only).
	sess, err := session.New(session.NewParams{
		CorrelationID: corr,
		AGID:          agid,
		Action:        body.Action,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
		return
	}
	if err := r.sessions.Append(sess); err != nil {
		// Duplicate correlation_id → 409 (append-only invariant).
		writeError(w, http.StatusConflict, "DUPLICATE_CORRELATION_ID", err.Error())
		return
	}

	// Skeleton routing target — real M12 dispatch will route by action
	// to the owning chora-side agent.
	routedTo := "skeleton:" + body.Action

	// Compute response and mark session complete.
	resp := invokeResponse{
		CorrelationID: corr,
		AGID:          agid,
		Action:        body.Action,
		Status:        "completed",
		RoutedTo:      routedTo,
		Echo:          body.Params,
	}

	respBytes, _ := json.Marshal(resp)
	if err := sess.Complete(len(respBytes)); err != nil {
		log.Printf("session complete error correlation_id=%s err=%v", corr, err)
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respBytes)
}

// -----------------------------------------------------------------------------
// POST /a2a/v1/partners (register) + GET /a2a/v1/partners/{agid}
// -----------------------------------------------------------------------------

type registerPartnerRequest struct {
	AGID            string   `json:"agid"`
	Name            string   `json:"name"`
	AllowedScopes   []string `json:"allowed_scopes"`
	RateLimitPerMin int      `json:"rate_limit_per_minute"`
	QuotaPerDay     int      `json:"quota_per_day"`
}

// partnerResponse — NO gcid field (AGID-only invariant).
type partnerResponse struct {
	AGID            string   `json:"agid"`
	Name            string   `json:"name"`
	AllowedScopes   []string `json:"allowed_scopes"`
	RateLimitPerMin int      `json:"rate_limit_per_minute"`
	QuotaPerDay     int      `json:"quota_per_day"`
	Status          string   `json:"status"`
	CreatedAt       string   `json:"created_at"`
}

func (r *Router) partnersCollection(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "use POST")
		return
	}
	agid := req.Header.Get("X-AGID")
	if agid == "" {
		writeError(w, http.StatusBadRequest, "MISSING_AGID", "X-AGID header required on /a2a/v1/* endpoints")
		return
	}
	// Real impl in M12 will gate on internal IAM (admin role).
	var body registerPartnerRequest
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_BODY", "request body is not valid JSON")
		return
	}
	p, err := partner.New(partner.NewParams{
		AGID:            body.AGID,
		Name:            body.Name,
		AllowedScopes:   body.AllowedScopes,
		RateLimitPerMin: body.RateLimitPerMin,
		QuotaPerDay:     body.QuotaPerDay,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_PARTNER", err.Error())
		return
	}
	if err := r.partners.Put(p); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}
	r.limiter.Configure(p.AGID, p.RateLimitPerMin, time.Minute)
	writeJSON(w, http.StatusCreated, toPartnerResponse(p))
}

func (r *Router) partnersByAGID(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "use GET")
		return
	}
	agid := req.Header.Get("X-AGID")
	if agid == "" {
		writeError(w, http.StatusBadRequest, "MISSING_AGID", "X-AGID header required on /a2a/v1/* endpoints")
		return
	}
	target := strings.TrimPrefix(req.URL.Path, "/a2a/v1/partners/")
	if target == "" {
		writeError(w, http.StatusBadRequest, "MISSING_PARTNER_AGID", "agid path param required")
		return
	}
	p, err := r.partners.Get(target)
	if errors.Is(err, inmem.ErrNotFound) {
		writeError(w, http.StatusNotFound, "PARTNER_NOT_FOUND", "no partner registered for agid="+target)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, toPartnerResponse(p))
}

func toPartnerResponse(p *partner.Partner) partnerResponse {
	return partnerResponse{
		AGID:            p.AGID,
		Name:            p.Name,
		AllowedScopes:   p.AllowedScopes,
		RateLimitPerMin: p.RateLimitPerMin,
		QuotaPerDay:     p.QuotaPerDay,
		Status:          string(p.Status),
		CreatedAt:       p.CreatedAt.Format(time.RFC3339),
	}
}

// -----------------------------------------------------------------------------
// GET /a2a/v1/sessions/{correlation_id}
// -----------------------------------------------------------------------------

// sessionResponse — NO gcid field; this is a partner-agent invocation log.
type sessionResponse struct {
	CorrelationID     string `json:"correlation_id"`
	AGID              string `json:"agid"`
	Action            string `json:"action"`
	Status            string `json:"status"`
	StartedAt         string `json:"started_at"`
	EndedAt           string `json:"ended_at,omitempty"`
	ResponseSizeBytes int    `json:"response_size_bytes"`
	ErrorCode         string `json:"error_code,omitempty"`
}

func (r *Router) sessionsByCorrelation(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "use GET")
		return
	}
	agid := req.Header.Get("X-AGID")
	if agid == "" {
		writeError(w, http.StatusBadRequest, "MISSING_AGID", "X-AGID header required on /a2a/v1/* endpoints")
		return
	}
	corr := strings.TrimPrefix(req.URL.Path, "/a2a/v1/sessions/")
	if corr == "" {
		writeError(w, http.StatusBadRequest, "MISSING_CORRELATION_ID", "correlation_id path param required")
		return
	}
	sess, err := r.sessions.GetByCorrelationID(corr)
	if errors.Is(err, inmem.ErrNotFound) {
		writeError(w, http.StatusNotFound, "SESSION_NOT_FOUND", "no session with correlation_id="+corr)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}
	resp := sessionResponse{
		CorrelationID:     sess.CorrelationID,
		AGID:              sess.AGID,
		Action:            sess.Action,
		Status:            string(sess.Status),
		StartedAt:         sess.StartedAt.Format(time.RFC3339),
		ResponseSizeBytes: sess.ResponseSizeBytes,
		ErrorCode:         sess.ErrorCode,
	}
	if sess.EndedAt != nil {
		resp.EndedAt = sess.EndedAt.Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, resp)
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

type errorBody struct {
	Error         string `json:"error"`
	Code          string `json:"code"`
	CorrelationID string `json:"correlation_id,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("encode error: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, errorBody{Error: msg, Code: code})
}

// decodeJWTSubject decodes the payload of a Bearer JWT WITHOUT verifying
// the signature. Skeleton-only — full verification (against Identity
// Platform JWKS) lands in M14.
func decodeJWTSubject(authHeader string) (string, error) {
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", errors.New("authorization header missing Bearer prefix")
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return "", errors.New("malformed JWT (need at least header.payload)")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// Try standard base64 with padding stripped — JWTs sometimes have it.
		payload, err = base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			return "", err
		}
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", err
	}
	if sub, ok := claims["sub"].(string); ok {
		return sub, nil
	}
	return "", nil
}
