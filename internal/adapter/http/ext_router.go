// Package httpadapter — ExtRouter wires the partner-facing REST endpoints
// per ADR-132 §8 + the user task spec for the M11 skeleton.
//
// External (partner-facing) routes:
//
//	POST /partners/register                    public submit (anyone can request onboarding)
//	GET  /partners/{id}                        partner detail (registration + state)
//	POST /admin/partners/{id}:approve          mints AGID + one-time API key
//	POST /admin/partners/{id}:suspend          policy-violation + compliance review
//	POST /admin/partners/{id}:reinstate        un-suspend
//	GET  /admin/partners?status=X              admin queue
//	POST /contracts/{partner_id}               register an A2AContract for a partner
//	GET  /contracts/{partner_id}               list partner contracts (versioned)
//	GET  /contracts/{partner_id}/openapi.yaml  per-consumer OpenAPI spec subset
//	POST /a2a/invoke                           main partner-facing capability invoker
//	GET  /a2a/audit?partner_id=X               invocation audit trail
//	POST /admin/byoa/{tenant_id}/{provider}    register BYOA encrypted external LLM key
//	DELETE /admin/byoa/{tenant_id}/{provider}  revoke BYOA key
//	POST /admin/mcp/{tenant_id}                configure per-tenant MCP gateway add-on
//	POST /admin/mcp/{tenant_id}:suspend        pause a tenant's MCP add-on (resolve → 403, not revoked)
//	POST /admin/mcp/{tenant_id}:reinstate      un-pause a suspended MCP add-on
//	POST /admin/mcp/_resolve                   MCP-gateway → A2A-gateway API-key resolution (M12)
//	POST /admin/dns/verify                     DNS-TXT verification trigger (test/admin)
//
// CRITICAL: NO routes return or accept a `gcid` field — all partner-facing
// audit/invoke is AGID-only (CLAUDE.md §1).
//
// AP-01: the production OpenAPI contract lives in
// chora-contracts/openapi/a2a-gateway.yaml; this router is the canonical
// implementation.
package httpadapter

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/dns"
	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/events"
	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/rate_limiter"
	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/repo"
	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/repo/inmem"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/byoa"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/contract"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/invocation"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/mcp"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/partner"
)

// ExtConfig is the dependency injection bundle for the partner-facing router.
type ExtConfig struct {
	Registrations repo.RegistrationStore
	Contracts     repo.ContractStore
	Invocations   repo.InvocationStore
	// BYOAKeys is env-selected (inmem default | pg durable) by
	// cmd/server/bootstrap.go's chooseBYOAKeyBackend (W0-F1, CHO-2198).
	BYOAKeys repo.BYOAKeyStore
	// MCPConfigs is env-selected (inmem default | pg durable) by
	// cmd/server/bootstrap.go's chooseMCPConfigBackend, same switch as
	// Registrations/Contracts/Invocations above.
	MCPConfigs  repo.MCPConfigStore
	Publisher   events.Publisher
	RateLimiter *rate_limiter.TokenBucket
	DNSResolver dns.Resolver

	// SourceProject overrides events.SourceProject for tests.
	SourceProject string
}

// ExtRouter is the partner-facing router (registered behind the platform ingress
// → a2a.chora.site).
type ExtRouter struct {
	mux           *http.ServeMux
	cfg           ExtConfig
	registrations repo.RegistrationStore
	contracts     repo.ContractStore
	invocations   repo.InvocationStore
	byoaKeys      repo.BYOAKeyStore
	mcpConfigs    repo.MCPConfigStore
	mcpResolver   *mcp.Resolver
	publisher     events.Publisher
	rl            *rate_limiter.TokenBucket
	dns           dns.Resolver
}

// NewExtRouter constructs the partner-facing router.
func NewExtRouter(cfg ExtConfig) *ExtRouter {
	if cfg.Publisher == nil {
		cfg.Publisher = events.NewInMemoryPublisher()
	}
	if cfg.RateLimiter == nil {
		cfg.RateLimiter = rate_limiter.NewTokenBucket()
	}
	if cfg.DNSResolver == nil {
		cfg.DNSResolver = dns.NewMockResolver()
	}
	if cfg.BYOAKeys == nil {
		cfg.BYOAKeys = inmem.NewBYOAKeyRepo()
	}
	if cfg.MCPConfigs == nil {
		cfg.MCPConfigs = inmem.NewMCPConfigRepo()
	}
	r := &ExtRouter{
		mux:           http.NewServeMux(),
		cfg:           cfg,
		registrations: cfg.Registrations,
		contracts:     cfg.Contracts,
		invocations:   cfg.Invocations,
		byoaKeys:      cfg.BYOAKeys,
		mcpConfigs:    cfg.MCPConfigs,
		// cfg.MCPConfigs is defaulted non-nil above; repo.MCPConfigStore
		// satisfies mcp.Store via its ByAPIKeyHash method (reverse
		// key-hash lookup) regardless of which backend (inmem/pg) is wired.
		mcpResolver: mcp.NewResolver(cfg.MCPConfigs),
		publisher:   cfg.Publisher,
		rl:          cfg.RateLimiter,
		dns:         cfg.DNSResolver,
	}
	r.routes()
	return r
}

// ServeHTTP makes ExtRouter an http.Handler.
func (r *ExtRouter) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mux.ServeHTTP(w, req)
}

// publish emits e via the configured publisher. Every call site in this
// file invokes publish AFTER the domain state mutation has already
// committed (or, on the invoke/dns-verify error branches, after the
// response's business-decision error code has already been chosen) —
// so a Publish failure is intentionally best-effort: turning it into an
// HTTP error here would either mislabel an already-successful mutation
// as failed (inviting client retries that mint duplicate IDs — these
// routes accept no caller-supplied idempotency key) or clobber a
// correct 403/422/429 with a meaningless 500. Best-effort does NOT mean
// silent: Publish can fail for real reasons in production (the
// TransactionalOutboxPublisher writes to a2a_outbox_events — see
// internal/adapter/outbox/publisher.go — which can fail on connection
// loss, constraint violation, or an unregistered/malformed topic), so
// the error is always surfaced via a loud log line instead of `_ =`.
func (r *ExtRouter) publish(e events.Event) {
	if err := r.publisher.Publish(e); err != nil {
		log.Printf("publish error topic=%s tenant_id=%s err=%v", e.Topic, e.TenantID, err)
	}
}

func (r *ExtRouter) routes() {
	r.mux.HandleFunc("/partners/register", r.registerPartner)
	r.mux.HandleFunc("/partners/", r.partnerDetail)
	r.mux.HandleFunc("/admin/partners", r.adminPartnerQueue)
	r.mux.HandleFunc("/admin/partners/", r.adminPartnerOps)
	r.mux.HandleFunc("/contracts/", r.contractRoutes)
	r.mux.HandleFunc("/a2a/invoke", r.invoke)
	r.mux.HandleFunc("/a2a/audit", r.audit)
	r.mux.HandleFunc("/admin/byoa/", r.byoaRoutes)
	// Exact /admin/mcp/_resolve is registered before the /admin/mcp/ subtree so
	// ServeMux's most-specific match routes it to the resolver, not the
	// per-tenant config handler (which would treat "_resolve" as a tenant_id).
	r.mux.HandleFunc("/admin/mcp/_resolve", r.mcpResolve)
	r.mux.HandleFunc("/admin/mcp/", r.mcpRoutes)
	r.mux.HandleFunc("/admin/dns/verify", r.dnsVerify)
}

// -----------------------------------------------------------------------------
// POST /partners/register
// -----------------------------------------------------------------------------

type registerReqBody struct {
	OrgName            string   `json:"org_name"`
	ContactEmail       string   `json:"contact_email"`
	Capabilities       []string `json:"capabilities"`
	RequestedRateLimit int      `json:"requested_rate_limit"`
	PartnerDomain      string   `json:"partner_domain,omitempty"` // for DNS-TXT verification
}

type registerRespBody struct {
	ID                 string   `json:"id"`
	OrgName            string   `json:"org_name"`
	ContactEmail       string   `json:"contact_email"`
	Capabilities       []string `json:"capabilities"`
	RequestedRateLimit int      `json:"requested_rate_limit"`
	State              string   `json:"state"`
	PartnerDomain      string   `json:"partner_domain,omitempty"`
	DNSVerifyToken     string   `json:"dns_verify_token,omitempty"`
	DNSVerifyRecord    string   `json:"dns_verify_record,omitempty"`
	CreatedAt          string   `json:"created_at"`
}

func (r *ExtRouter) registerPartner(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeExtError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "use POST")
		return
	}
	var body registerReqBody
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeExtError(w, http.StatusBadRequest, "BAD_BODY", err.Error())
		return
	}
	id := newUUIDv7()
	reg, err := partner.NewRegistration(partner.RegistrationParams{
		ID:                 id,
		OrgName:            body.OrgName,
		ContactEmail:       body.ContactEmail,
		Capabilities:       body.Capabilities,
		RequestedRateLimit: body.RequestedRateLimit,
	})
	if err != nil {
		writeExtError(w, http.StatusBadRequest, "INVALID_REGISTRATION", err.Error())
		return
	}

	// DNS-TXT verification scaffold — if the registrant declared a
	// partner_domain, we mint a verification token and persist it on the
	// registration so /admin/dns/verify can confirm it later.
	dnsToken := ""
	dnsRecord := ""
	if strings.TrimSpace(body.PartnerDomain) != "" {
		dnsToken = newRandomToken()
		dnsRecord = "_chora-a2a." + body.PartnerDomain + " IN TXT \"chora-a2a-verify=" + dnsToken + "\""
		reg.PartnerDomain = strings.TrimSpace(body.PartnerDomain)
		reg.DNSVerifyToken = dnsToken
	}

	if err := r.registrations.Put(reg); err != nil {
		writeExtError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}

	traceparent := req.Header.Get("traceparent")
	r.publish(events.Event{
		Topic:       "chora.a2a.partner.registered.v1",
		Payload:     map[string]any{"registration_id": reg.ID, "org_name": reg.OrgName},
		TenantID:    tenantOrPlatform(req),
		Traceparent: traceparent,
		// IMDA D1 accountability — onboarding evidence.
		IMDADimension:      "accountability",
		IMDALifecycleStage: "runtime",
	})

	writeExtJSON(w, http.StatusCreated, toRegistrationResponse(reg, dnsRecord))
}

// -----------------------------------------------------------------------------
// GET /partners/{id}
// -----------------------------------------------------------------------------

func (r *ExtRouter) partnerDetail(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		writeExtError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "use GET")
		return
	}
	id := strings.TrimPrefix(req.URL.Path, "/partners/")
	if strings.Contains(id, "/") || id == "" {
		writeExtError(w, http.StatusBadRequest, "BAD_PATH", "expected /partners/{id}")
		return
	}
	reg, err := r.registrations.Get(id)
	if errors.Is(err, inmem.ErrNotFound) {
		writeExtError(w, http.StatusNotFound, "PARTNER_NOT_FOUND", "no partner with id="+id)
		return
	}
	if err != nil {
		writeExtError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}
	writeExtJSON(w, http.StatusOK, toRegistrationResponse(reg, ""))
}

// -----------------------------------------------------------------------------
// POST /admin/partners/{id}:approve | :suspend | :reinstate
// -----------------------------------------------------------------------------

type approveBody struct {
	ApproverGCID string `json:"approver_gcid"`
	Tier         string `json:"tier"`
}

type suspendBody struct {
	ApproverGCID string `json:"approver_gcid"`
	Reason       string `json:"reason"`
}

type approveResp struct {
	ID         string `json:"id"`
	State      string `json:"state"`
	AGID       string `json:"agid"`
	APIKey     string `json:"api_key"` // ONE-TIME plaintext
	Tier       string `json:"tier"`
	ApprovedAt string `json:"approved_at"`
}

func (r *ExtRouter) adminPartnerOps(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeExtError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "use POST")
		return
	}
	rest := strings.TrimPrefix(req.URL.Path, "/admin/partners/")
	idx := strings.LastIndex(rest, ":")
	if idx <= 0 || idx == len(rest)-1 {
		writeExtError(w, http.StatusBadRequest, "BAD_PATH", "expected /admin/partners/{id}:{op}")
		return
	}
	id := rest[:idx]
	op := rest[idx+1:]
	reg, err := r.registrations.Get(id)
	if errors.Is(err, inmem.ErrNotFound) {
		writeExtError(w, http.StatusNotFound, "PARTNER_NOT_FOUND", "no partner with id="+id)
		return
	}
	if err != nil {
		writeExtError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}

	traceparent := req.Header.Get("traceparent")
	tenantID := tenantOrPlatform(req)

	switch op {
	case "approve":
		var body approveBody
		_ = json.NewDecoder(req.Body).Decode(&body)
		tier := partner.Tier(strings.ToLower(body.Tier))
		res, err := reg.Approve(partner.ApprovalParams{
			ApprovedByGCID: body.ApproverGCID,
			Tier:           tier,
		})
		if err != nil {
			// State-machine violation → 409.
			writeExtError(w, http.StatusConflict, "APPROVE_FAILED", err.Error())
			return
		}
		_ = r.registrations.Put(reg)
		// Configure rate-limiter at tier defaults.
		r.rl.Configure(res.AGID, rate_limiter.PolicyForTier(string(tier)))
		// chora.a2a.partner.approved.v1 carries the AGID; we DO NOT also
		// emit chora.a2a.agid.registered.v1 here because the partner
		// approval is the canonical onboarding event. agid.registered.v1
		// is reserved for the future case of additional AGIDs minted
		// post-approval (e.g. multi-instance agents — task spec §2).
		r.publish(events.Event{
			Topic: "chora.a2a.partner.approved.v1",
			Payload: map[string]any{
				"registration_id": reg.ID, "agid": res.AGID, "tier": string(tier),
			},
			TenantID:           tenantID,
			Traceparent:        traceparent,
			IMDADimension:      "accountability",
			IMDALifecycleStage: "runtime",
		})
		writeExtJSON(w, http.StatusOK, approveResp{
			ID: reg.ID, State: string(reg.State), AGID: res.AGID,
			APIKey:     res.APIKeyPlaintext,
			Tier:       string(tier),
			ApprovedAt: reg.ApprovedAt.Format(time.RFC3339),
		})

	case "suspend":
		var body suspendBody
		_ = json.NewDecoder(req.Body).Decode(&body)
		if err := reg.SuspendRegistration(body.Reason, body.ApproverGCID); err != nil {
			writeExtError(w, http.StatusConflict, "SUSPEND_FAILED", err.Error())
			return
		}
		_ = r.registrations.Put(reg)
		r.publish(events.Event{
			Topic: "chora.a2a.partner.suspended.v1",
			Payload: map[string]any{
				"registration_id": reg.ID, "agid": reg.AGID, "reason": body.Reason,
			},
			TenantID:           tenantID,
			Traceparent:        traceparent,
			IMDADimension:      "fairness_and_human_oversight",
			IMDALifecycleStage: "runtime",
		})
		writeExtJSON(w, http.StatusOK, map[string]any{"id": reg.ID, "state": string(reg.State)})

	case "reinstate":
		var body suspendBody // shares actor field
		_ = json.NewDecoder(req.Body).Decode(&body)
		if err := reg.ReinstateRegistration(body.ApproverGCID); err != nil {
			writeExtError(w, http.StatusConflict, "REINSTATE_FAILED", err.Error())
			return
		}
		_ = r.registrations.Put(reg)
		r.publish(events.Event{
			Topic: "chora.a2a.partner.reinstated.v1",
			Payload: map[string]any{
				"registration_id": reg.ID, "agid": reg.AGID,
			},
			TenantID:           tenantID,
			Traceparent:        traceparent,
			IMDADimension:      "accountability",
			IMDALifecycleStage: "runtime",
		})
		writeExtJSON(w, http.StatusOK, map[string]any{"id": reg.ID, "state": string(reg.State)})

	case "revoke":
		// Revoke is a terminal soft-delete plus AGID revocation event.
		reg.SoftDeleteRegistration()
		_ = r.registrations.Put(reg)
		r.publish(events.Event{
			Topic: "chora.a2a.agid.revoked.v1",
			Payload: map[string]any{
				"registration_id": reg.ID, "agid": reg.AGID,
			},
			TenantID:           tenantID,
			Traceparent:        traceparent,
			IMDADimension:      "accountability",
			IMDALifecycleStage: "runtime",
		})
		writeExtJSON(w, http.StatusOK, map[string]any{"id": reg.ID, "state": "revoked"})

	default:
		writeExtError(w, http.StatusBadRequest, "BAD_OP", "unknown op: "+op)
	}
}

// -----------------------------------------------------------------------------
// GET /admin/partners?status=X
// -----------------------------------------------------------------------------

func (r *ExtRouter) adminPartnerQueue(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		writeExtError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "use GET")
		return
	}
	status := strings.ToLower(req.URL.Query().Get("status"))
	var s partner.RegistrationState
	switch status {
	case "pending":
		s = partner.RegistrationPending
	case "approved":
		s = partner.RegistrationApproved
	case "suspended":
		s = partner.RegistrationSuspended
	default:
		writeExtError(w, http.StatusBadRequest, "BAD_STATUS",
			"status must be one of pending|approved|suspended")
		return
	}
	regs, err := r.registrations.ListByStatus(s)
	if err != nil {
		writeExtError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}
	out := make([]map[string]any, 0, len(regs))
	for _, reg := range regs {
		out = append(out, registrationToMap(reg))
	}
	writeExtJSON(w, http.StatusOK, map[string]any{"partners": out})
}

// -----------------------------------------------------------------------------
// /contracts/{partner_id}  POST + GET + GET .../openapi.yaml
// -----------------------------------------------------------------------------

type contractRequest struct {
	AuthMethod   string            `json:"auth_method"`
	Capabilities []contractCapBody `json:"capabilities"`
}

type contractCapBody struct {
	Name            string `json:"name"`
	Tier            string `json:"tier"`
	RateLimitPerMin int    `json:"rate_limit_per_minute"`
}

type contractResp struct {
	ID           string           `json:"id"`
	PartnerID    string           `json:"partner_id"`
	AuthMethod   string           `json:"auth_method"`
	Capabilities []map[string]any `json:"capabilities"`
	Version      int              `json:"version"`
	SupersedesID string           `json:"supersedes_id,omitempty"`
	SunsetAt     string           `json:"sunset_at,omitempty"`
	CreatedAt    string           `json:"created_at"`
}

func (r *ExtRouter) contractRoutes(w http.ResponseWriter, req *http.Request) {
	rest := strings.TrimPrefix(req.URL.Path, "/contracts/")
	if rest == "" {
		writeExtError(w, http.StatusBadRequest, "BAD_PATH", "expected /contracts/{partner_id}[/openapi.yaml]")
		return
	}
	parts := strings.SplitN(rest, "/", 2)
	pid := parts[0]
	suffix := ""
	if len(parts) == 2 {
		suffix = parts[1]
	}

	if suffix == "openapi.yaml" {
		r.contractOpenAPI(w, req, pid)
		return
	}

	switch req.Method {
	case http.MethodPost:
		r.contractCreate(w, req, pid)
	case http.MethodGet:
		r.contractList(w, req, pid)
	default:
		writeExtError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "use POST or GET")
	}
}

func (r *ExtRouter) contractCreate(w http.ResponseWriter, req *http.Request, pid string) {
	reg, err := r.registrations.Get(pid)
	if errors.Is(err, inmem.ErrNotFound) {
		writeExtError(w, http.StatusNotFound, "PARTNER_NOT_FOUND", "no partner with id="+pid)
		return
	}
	if err != nil {
		writeExtError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}
	if !reg.IsActive() {
		writeExtError(w, http.StatusConflict, "PARTNER_NOT_APPROVED",
			"partner registration must be approved before contracts can be created")
		return
	}

	var body contractRequest
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeExtError(w, http.StatusBadRequest, "BAD_BODY", err.Error())
		return
	}

	caps := make([]contract.Capability, 0, len(body.Capabilities))
	for _, c := range body.Capabilities {
		caps = append(caps, contract.Capability{
			Name:            c.Name,
			Tier:            contract.Tier(strings.ToLower(c.Tier)),
			RateLimitPerMin: c.RateLimitPerMin,
		})
	}
	c, err := contract.New(contract.NewParams{
		ID:           newUUIDv7(),
		PartnerID:    pid,
		AuthMethod:   contract.AuthMethod(strings.ToLower(body.AuthMethod)),
		Capabilities: caps,
	})
	if err != nil {
		writeExtError(w, http.StatusBadRequest, "INVALID_CONTRACT", err.Error())
		return
	}
	_ = r.contracts.Put(c)

	// Configure per-AGID rate-limit at the lowest contracted rate so callers
	// cannot exceed it. Burst scales with the rate but is bounded so a
	// freshly-onboarded partner cannot blow through their entire minute's
	// quota in the first second.
	if reg.AGID != "" && len(caps) > 0 {
		minRate := caps[0].RateLimitPerMin
		for _, x := range caps[1:] {
			if x.RateLimitPerMin < minRate {
				minRate = x.RateLimitPerMin
			}
		}
		// Burst = max(1, min(rate/60+1, rate/4)). For low-rate contracts
		// (e.g. 1/min) this collapses to 1. For higher rates we allow a
		// small burst proportional to the rate.
		burst := minRate / 60
		if burst < 1 {
			burst = 1
		}
		if cap := minRate / 4; cap > burst+1 {
			burst = cap
		}
		r.rl.Configure(reg.AGID, rate_limiter.Policy{
			RatePerMinute: minRate,
			Burst:         burst,
		})
	}

	r.publish(events.Event{
		Topic: "chora.a2a.contract.published.v1",
		Payload: map[string]any{
			"contract_id": c.ID, "partner_id": pid, "version": c.Version,
		},
		TenantID:           tenantOrPlatform(req),
		Traceparent:        req.Header.Get("traceparent"),
		IMDADimension:      "transparency",
		IMDALifecycleStage: "runtime",
	})

	writeExtJSON(w, http.StatusCreated, toContractResponse(c))
}

func (r *ExtRouter) contractList(w http.ResponseWriter, req *http.Request, pid string) {
	if _, err := r.registrations.Get(pid); errors.Is(err, inmem.ErrNotFound) {
		writeExtError(w, http.StatusNotFound, "PARTNER_NOT_FOUND", "no partner with id="+pid)
		return
	}
	cs, err := r.contracts.ListByPartner(pid)
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

// contractOpenAPI returns a per-consumer OpenAPI YAML subset listing only the
// capabilities the partner is entitled to invoke.
func (r *ExtRouter) contractOpenAPI(w http.ResponseWriter, req *http.Request, pid string) {
	if req.Method != http.MethodGet {
		writeExtError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "use GET")
		return
	}
	cs, err := r.contracts.ListByPartner(pid)
	if err != nil || len(cs) == 0 {
		writeExtError(w, http.StatusNotFound, "NO_CONTRACT", "no active contracts for partner="+pid)
		return
	}
	// Render YAML manually — keeps the skeleton dep-free; M12 wires
	// chora-contracts/openapi/a2a-gateway.yaml as the canonical source.
	var sb strings.Builder
	sb.WriteString("openapi: 3.0.3\n")
	sb.WriteString("info:\n")
	sb.WriteString("  title: \"chora-a2a-gateway — partner OpenAPI subset\"\n")
	fmt.Fprintf(&sb, "  description: \"Per-consumer subset for partner_id=%s. Only capabilities granted by an active A2AContract are listed.\"\n", pid)
	sb.WriteString("  version: \"1.0.0\"\n")
	sb.WriteString("servers:\n")
	sb.WriteString("  - url: https://a2a.chora.site\n")
	sb.WriteString("    description: \"the platform ingress → chora-a2a-gateway\"\n")
	sb.WriteString("paths:\n")
	seen := make(map[string]struct{})
	for _, c := range cs {
		for _, cap := range c.Capabilities {
			if _, ok := seen[cap.Name]; ok {
				continue
			}
			seen[cap.Name] = struct{}{}
			fmt.Fprintf(&sb, "  /a2a/invoke#%s:\n", cap.Name)
			sb.WriteString("    post:\n")
			fmt.Fprintf(&sb, "      summary: \"%s\"\n", cap.Name)
			fmt.Fprintf(&sb, "      x-chora-tier: %s\n", string(cap.Tier))
			fmt.Fprintf(&sb, "      x-chora-rate-limit-per-minute: %d\n", cap.RateLimitPerMin)
			fmt.Fprintf(&sb, "      x-chora-contract-version: %d\n", c.Version)
			sb.WriteString("      requestBody:\n")
			sb.WriteString("        required: true\n")
			sb.WriteString("        content:\n")
			sb.WriteString("          application/json:\n")
			sb.WriteString("            schema:\n")
			sb.WriteString("              type: object\n")
			sb.WriteString("              properties:\n")
			sb.WriteString("                capability: { type: string }\n")
			sb.WriteString("                params: { type: object }\n")
			sb.WriteString("      responses:\n")
			sb.WriteString("        \"200\": { description: completed }\n")
			sb.WriteString("        \"403\": { description: scope_denied }\n")
			sb.WriteString("        \"429\": { description: rate_limited }\n")
		}
	}
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(sb.String()))
}

// -----------------------------------------------------------------------------
// POST /a2a/invoke
// -----------------------------------------------------------------------------

type invokeBody struct {
	Capability string         `json:"capability"`
	Params     map[string]any `json:"params"`
}

func (r *ExtRouter) invoke(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeExtError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "use POST")
		return
	}
	pid := req.Header.Get("X-Partner-Id")
	if pid == "" {
		writeExtError(w, http.StatusBadRequest, "MISSING_PARTNER_ID", "X-Partner-Id header required")
		return
	}
	apiKey := req.Header.Get("X-API-Key")
	if apiKey == "" {
		writeExtError(w, http.StatusUnauthorized, "MISSING_API_KEY", "X-API-Key header required")
		return
	}
	corr := req.Header.Get("X-Correlation-Id")
	if corr == "" {
		writeExtError(w, http.StatusBadRequest, "MISSING_CORRELATION_ID", "X-Correlation-Id header required")
		return
	}
	traceparent := req.Header.Get("traceparent")

	reg, err := r.registrations.Get(pid)
	if errors.Is(err, inmem.ErrNotFound) {
		writeExtError(w, http.StatusUnauthorized, "INVALID_API_KEY", "no partner with id="+pid)
		return
	}
	if err != nil {
		writeExtError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}
	// Use the timing-safe key comparator that ignores state — we want a
	// suspended partner with the right key to receive 403, not 401.
	if !verifyKeyHashOnly(reg, apiKey) {
		writeExtError(w, http.StatusUnauthorized, "INVALID_API_KEY", "api key did not verify")
		return
	}
	if !reg.IsActive() {
		writeExtError(w, http.StatusForbidden, "PARTNER_SUSPENDED", "partner state="+string(reg.State))
		return
	}

	var body invokeBody
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeExtError(w, http.StatusBadRequest, "BAD_BODY", err.Error())
		return
	}
	if strings.TrimSpace(body.Capability) == "" {
		writeExtError(w, http.StatusBadRequest, "MISSING_CAPABILITY", "body.capability required")
		return
	}

	// Look up an active contract that grants the capability.
	cs, _ := r.contracts.ListByPartner(pid)
	var grantedCap *contract.Capability
	var grantedContract *contract.Contract
	for _, c := range cs {
		if !c.IsActive() {
			continue
		}
		for i, cap := range c.Capabilities {
			if cap.Name == body.Capability {
				grantedCap = &c.Capabilities[i]
				grantedContract = c
				break
			}
		}
		if grantedCap != nil {
			break
		}
	}

	tenantID := tenantOrPlatform(req)

	if grantedCap == nil {
		// Scope denied — append-only audit trail still records the event.
		inv := mustNewInvocation(reg, body.Capability, corr, traceparent)
		_ = inv.ScopeDeny("CAPABILITY_NOT_IN_CONTRACT")
		_ = r.invocations.Append(inv)
		r.publish(events.Event{
			Topic: "chora.a2a.invocation.scope_denied.v1",
			Payload: map[string]any{
				"invocation_id": inv.ID, "agid": inv.AGID, "capability": inv.Capability,
				"partner_id": inv.PartnerID, "correlation_id": inv.CorrelationID,
			},
			TenantID:           tenantID,
			Traceparent:        traceparent,
			IMDADimension:      "fairness_and_human_oversight",
			IMDALifecycleStage: "runtime",
		})
		writeExtError(w, http.StatusForbidden, "SCOPE_DENIED",
			"capability not in any active contract for partner="+pid)
		return
	}

	// Rate-limit at the contract's per-capability rate (configured at
	// contract creation; we do NOT reconfigure on every invoke or the
	// bucket would refill back to Burst on each call).
	if !r.rl.Allow(reg.AGID) {
		retry := r.rl.RetryAfter(reg.AGID)
		secs := int(retry.Seconds())
		if secs < 1 {
			secs = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(secs))

		inv := mustNewInvocation(reg, body.Capability, corr, traceparent)
		_ = inv.RateLimit()
		_ = r.invocations.Append(inv)
		r.publish(events.Event{
			Topic: "chora.a2a.invocation.rate_limited.v1",
			Payload: map[string]any{
				"invocation_id": inv.ID, "agid": inv.AGID, "capability": inv.Capability,
				"partner_id": inv.PartnerID, "correlation_id": inv.CorrelationID,
			},
			TenantID:           tenantID,
			Traceparent:        traceparent,
			IMDADimension:      "fairness_and_human_oversight",
			IMDALifecycleStage: "runtime",
		})
		writeExtError(w, http.StatusTooManyRequests, "RATE_LIMITED",
			"per-AGID rate limit exceeded; retry after "+strconv.Itoa(secs)+"s")
		return
	}

	inv := mustNewInvocation(reg, body.Capability, corr, traceparent)
	if err := r.invocations.Append(inv); err != nil {
		writeExtError(w, http.StatusConflict, "DUPLICATE_CORRELATION", err.Error())
		return
	}

	// Skeleton echo response — real M12 dispatch routes to the owning
	// chora-side service via gRPC.
	type resp struct {
		InvocationID  string         `json:"invocation_id"`
		Status        string         `json:"status"`
		PartnerID     string         `json:"partner_id"`
		Capability    string         `json:"capability"`
		ContractID    string         `json:"contract_id"`
		ContractVer   int            `json:"contract_version"`
		LatencyMS     int            `json:"latency_ms"`
		CorrelationID string         `json:"correlation_id"`
		Echo          map[string]any `json:"echo,omitempty"`
	}
	respBody := resp{
		InvocationID:  inv.ID,
		Status:        "completed",
		PartnerID:     pid,
		Capability:    body.Capability,
		ContractID:    grantedContract.ID,
		ContractVer:   grantedContract.Version,
		CorrelationID: corr,
		Echo:          body.Params,
	}
	respBytes, _ := json.Marshal(respBody)
	_ = inv.Complete(len(respBytes))
	_ = r.invocations.Update(inv)
	respBody.LatencyMS = inv.LatencyMS

	r.publish(events.Event{
		Topic: "chora.a2a.invocation.completed.v1",
		Payload: map[string]any{
			"invocation_id":    inv.ID,
			"agid":             inv.AGID,
			"partner_id":       inv.PartnerID,
			"capability":       inv.Capability,
			"contract_id":      grantedContract.ID,
			"contract_version": grantedContract.Version,
			"correlation_id":   inv.CorrelationID,
			"latency_ms":       inv.LatencyMS,
			"response_size":    inv.ResponseSizeBytes,
		},
		TenantID:           tenantID,
		Traceparent:        traceparent,
		IMDADimension:      "transparency", // D2 — audit visibility
		IMDALifecycleStage: "runtime",
	})

	respBytes, _ = json.Marshal(respBody)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respBytes)
}

// -----------------------------------------------------------------------------
// GET /a2a/audit?partner_id=X
// -----------------------------------------------------------------------------

func (r *ExtRouter) audit(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		writeExtError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "use GET")
		return
	}
	pid := req.URL.Query().Get("partner_id")
	if pid == "" {
		writeExtError(w, http.StatusBadRequest, "MISSING_PARTNER_ID", "partner_id query required")
		return
	}
	invs, err := r.invocations.ListByPartner(pid)
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

// -----------------------------------------------------------------------------
// /admin/byoa/{tenant_id}/{provider}
// -----------------------------------------------------------------------------

type byoaRegisterBody struct {
	APIKeyPlaintext string `json:"api_key"`
	TenantMasterKey string `json:"tenant_master_key,omitempty"` // base64 32-byte key for AES-GCM. M12 fetches via Cloud KMS CMEK.
}

func (r *ExtRouter) byoaRoutes(w http.ResponseWriter, req *http.Request) {
	rest := strings.TrimPrefix(req.URL.Path, "/admin/byoa/")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		writeExtError(w, http.StatusBadRequest, "BAD_PATH",
			"expected /admin/byoa/{tenant_id}/{provider}")
		return
	}
	tenantID := parts[0]
	provider := parts[1]

	switch req.Method {
	case http.MethodPost, http.MethodPut:
		var body byoaRegisterBody
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			writeExtError(w, http.StatusBadRequest, "BAD_BODY", err.Error())
			return
		}
		if body.APIKeyPlaintext == "" {
			writeExtError(w, http.StatusBadRequest, "MISSING_API_KEY", "api_key required")
			return
		}
		entry, err := byoa.EncryptKey(byoa.EncryptParams{
			TenantID:        tenantID,
			Provider:        provider,
			APIKeyPlaintext: body.APIKeyPlaintext,
			TenantMasterKey: body.TenantMasterKey,
		})
		if err != nil {
			writeExtError(w, http.StatusBadRequest, "ENCRYPT_FAILED", err.Error())
			return
		}
		// W0-F1 (CHO-2198): the store is now durable — a Put CAN fail (DB
		// down / constraint). Surface it as 500 instead of swallowing, or a
		// 201 would claim a persisted key the durable store never wrote
		// (silent AUTH-state loss — the exact bug class this fix closes).
		if err := r.byoaKeys.Put(&repo.BYOAKeyEntry{
			TenantID:       tenantID,
			Provider:       provider,
			Ciphertext:     entry.Ciphertext,
			KeyFingerprint: entry.KeyFingerprint,
			RotatedAt:      time.Now().UTC(),
		}); err != nil {
			writeExtError(w, http.StatusInternalServerError, "BYOA_PERSIST_FAILED", err.Error())
			return
		}
		r.publish(events.Event{
			Topic: "chora.a2a.byoa_key.rotated.v1",
			Payload: map[string]any{
				"tenant_id": tenantID, "provider": provider, "key_fingerprint": entry.KeyFingerprint,
			},
			TenantID:           tenantID,
			Traceparent:        req.Header.Get("traceparent"),
			IMDADimension:      "safety_and_robustness",
			IMDALifecycleStage: "runtime",
		})
		writeExtJSON(w, http.StatusCreated, map[string]any{
			"tenant_id":       tenantID,
			"provider":        provider,
			"key_fingerprint": entry.KeyFingerprint,
			"rotated_at":      time.Now().UTC().Format(time.RFC3339),
		})

	case http.MethodDelete:
		// W0-F1 (CHO-2198): distinguish "absent" (404) from a durable-store
		// error (500). Previously any non-NotFound error fell through to a
		// 200 "revoked", masking a failed revoke — a security-relevant lie.
		if err := r.byoaKeys.SoftDelete(tenantID, provider); err != nil {
			if errors.Is(err, repo.ErrNotFound) {
				writeExtError(w, http.StatusNotFound, "BYOA_KEY_NOT_FOUND", "no key for tenant/provider")
				return
			}
			writeExtError(w, http.StatusInternalServerError, "BYOA_REVOKE_FAILED", err.Error())
			return
		}
		r.publish(events.Event{
			Topic:    "chora.a2a.byoa_key.revoked.v1",
			Payload:  map[string]any{"tenant_id": tenantID, "provider": provider},
			TenantID: tenantID, Traceparent: req.Header.Get("traceparent"),
			IMDADimension:      "safety_and_robustness",
			IMDALifecycleStage: "runtime",
		})
		writeExtJSON(w, http.StatusOK, map[string]any{"revoked": true})

	default:
		writeExtError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "use POST/PUT/DELETE")
	}
}

// -----------------------------------------------------------------------------
// /admin/mcp/{tenant_id}
// -----------------------------------------------------------------------------

type mcpConfigBody struct {
	// AllowedTools is intentionally NOT validated against the canonical MCP
	// tool catalogue here. That catalogue (internal/domain/tool.DefaultCatalog)
	// lives in chora-mcp-gateway — a separate Go module — so a2a-gateway has
	// no clean, non-duplicating source of truth to check against: importing
	// it is impossible (different module + internal/ package), and hardcoding
	// a parallel tool-name list here would be a cross-service DDD leak that
	// drifts the moment mcp-gateway adds/renames/removes a tool (silent
	// validation-vs-catalogue skew is worse than no validation). A typo'd
	// tool name here fails safe today — it just grants nothing, since
	// mcp.Resolver + chora-mcp-gateway's Catalog.FilterByAllowedNames only
	// ever matches by exact name. Correct home for this check is either
	// chora-mcp-gateway itself (reject unknown names before persisting the
	// resolved identity) or the H+ registration UI (client-side dropdown
	// sourced from mcp-gateway's /mcp/tools/list) — not a duplicated
	// allowlist inside a2a-gateway.
	AllowedTools []string `json:"allowed_tools"`
}

type mcpConfigResp struct {
	TenantID     string   `json:"tenant_id"`
	APIKey       string   `json:"api_key"` // ONE-TIME plaintext
	AllowedTools []string `json:"allowed_tools"`
}

func (r *ExtRouter) mcpRoutes(w http.ResponseWriter, req *http.Request) {
	rest := strings.TrimPrefix(req.URL.Path, "/admin/mcp/")
	if rest == "" || strings.Contains(rest, "/") {
		writeExtError(w, http.StatusBadRequest, "BAD_PATH", "expected /admin/mcp/{tenant_id}")
		return
	}
	// {tenant_id}:suspend | :reinstate — mirrors /admin/partners/{id}:{op}.
	if idx := strings.LastIndex(rest, ":"); idx > 0 && idx < len(rest)-1 {
		r.mcpConfigOp(w, req, rest[:idx], rest[idx+1:])
		return
	}
	tenantID := rest
	switch req.Method {
	case http.MethodPost, http.MethodPut:
		var body mcpConfigBody
		_ = json.NewDecoder(req.Body).Decode(&body)
		key := newRandomToken()
		now := time.Now().UTC()
		cfg := &inmem.MCPConfig{
			TenantID: tenantID,
			// Persist the SAME canonical credential digest the resolve path
			// re-derives (partner.HashAPIKey) so the write + read hashes can
			// never drift — and never an AGID-derived placeholder (CHO-1971).
			APIKeyHash:   partner.HashAPIKey(key),
			AllowedTools: append([]string(nil), body.AllowedTools...),
			CreatedAt:    now,
			UpdatedAt:    now,
		}
		_ = r.mcpConfigs.Put(cfg)
		writeExtJSON(w, http.StatusCreated, mcpConfigResp{
			TenantID: tenantID, APIKey: key, AllowedTools: cfg.AllowedTools,
		})
	case http.MethodGet:
		cfg, err := r.mcpConfigs.Get(tenantID)
		if errors.Is(err, inmem.ErrNotFound) {
			writeExtError(w, http.StatusNotFound, "MCP_CONFIG_NOT_FOUND", "no config for tenant")
			return
		}
		writeExtJSON(w, http.StatusOK, map[string]any{
			"tenant_id":     cfg.TenantID,
			"allowed_tools": cfg.AllowedTools,
			"suspended":     cfg.Suspended,
		})
	default:
		writeExtError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "use POST/PUT/GET")
	}
}

// -----------------------------------------------------------------------------
// POST /admin/mcp/{tenant_id}:suspend | :reinstate
// -----------------------------------------------------------------------------

// mcpConfigOp is the reversible admin pause/un-pause for a tenant's MCP
// add-on — the "key resolved but partner inactive" (403) leg of the frozen
// _resolve wire contract, mirroring adminPartnerOps' suspend/reinstate for
// partner.Registration. It is distinct from a hard DeletedAt revoke: a
// suspended add-on keeps its key hash live in the store (ByAPIKeyHash still
// finds the row) but mcp.Resolver turns Suspended=true into mcp.ErrInactive
// so mcpResolve answers 403, not 401 — chora-mcp-gateway's A2AClient already
// branches on this today (clients/a2a_client.go → auth.ErrPartnerInactive).
func (r *ExtRouter) mcpConfigOp(w http.ResponseWriter, req *http.Request, tenantID, op string) {
	if req.Method != http.MethodPost {
		writeExtError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "use POST")
		return
	}
	var suspended bool
	var topic string
	switch op {
	case "suspend":
		suspended, topic = true, "chora.a2a.mcp_addon.suspended.v1"
	case "reinstate":
		suspended, topic = false, "chora.a2a.mcp_addon.reinstated.v1"
	default:
		writeExtError(w, http.StatusBadRequest, "BAD_OP", "unknown op: "+op)
		return
	}
	if err := r.mcpConfigs.SetSuspended(tenantID, suspended); errors.Is(err, inmem.ErrNotFound) {
		writeExtError(w, http.StatusNotFound, "MCP_CONFIG_NOT_FOUND", "no config for tenant="+tenantID)
		return
	} else if err != nil {
		writeExtError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}
	r.publish(events.Event{
		Topic:              topic,
		Payload:            map[string]any{"tenant_id": tenantID},
		TenantID:           tenantOrPlatform(req),
		Traceparent:        req.Header.Get("traceparent"),
		IMDADimension:      "fairness_and_human_oversight",
		IMDALifecycleStage: "runtime",
	})
	writeExtJSON(w, http.StatusOK, map[string]any{"tenant_id": tenantID, "suspended": suspended})
}

// -----------------------------------------------------------------------------
// POST /admin/mcp/_resolve
// -----------------------------------------------------------------------------

// mcpResolveResp is the wire contract consumed by chora-mcp-gateway's
// clients.A2AClient.ResolveAPIKey (clients/a2a_client.go resolverResponse).
// Field names + casing MUST stay identical so the existing MCP client works
// unchanged: {agid, partner_name, tenant_id, allowed_scopes, active}.
type mcpResolveResp struct {
	AGID          string   `json:"agid"`
	PartnerName   string   `json:"partner_name"`
	TenantID      string   `json:"tenant_id"`
	AllowedScopes []string `json:"allowed_scopes"`
	Active        bool     `json:"active"`
}

// mcpResolve is the server side of the MCP↔A2A tenant-resolution seam. The MCP
// gateway submits an inbound MCP client's X-API-Key here; we hash it with the
// canonical credential digest (partner.HashAPIKey — the SAME hash provisioning
// stored), resolve the owning per-tenant add-on, and return the acting identity
// (agid + owning tenant + tool scopes + active).
//
// Gating: this route lives under the internal-only /admin/mcp/* prefix exactly
// like the sibling config routes — it is NOT exposed on the public partner API
// Gateway (a2a.chora.site serves only /a2a/* + /api/v1/a2a/*) and is reachable
// only by allow-listed internal principals (Istio authz, /admin/mcp/*). The
// resolved key IS the credential, so there is no separate admin token (the MCP
// client sends X-API-Key only).
//
// Fail loud: a blank key is a 400; an unknown/revoked/invalid key is a 401
// with NO identity body; a known-but-suspended add-on (mcpConfigOp :suspend)
// is a 403, also with NO identity body — never a fabricated or
// empty-but-200 identity.
func (r *ExtRouter) mcpResolve(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeExtError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "use POST")
		return
	}
	id, err := r.mcpResolver.Resolve(req.Context(), req.Header.Get("X-API-Key"))
	switch {
	case errors.Is(err, mcp.ErrMissingKey):
		writeExtError(w, http.StatusBadRequest, "MISSING_API_KEY", "X-API-Key header required")
		return
	case errors.Is(err, mcp.ErrInvalidKey):
		// 401 with NO identity body — the MCP client maps 401/404 → invalid key.
		writeExtError(w, http.StatusUnauthorized, "INVALID_API_KEY", "api key did not resolve to an active MCP add-on")
		return
	case errors.Is(err, mcp.ErrInactive):
		// 403 with NO identity body — key resolved to a real add-on that is
		// administratively suspended (mcpConfigOp :suspend), distinct from an
		// unknown/revoked key. The MCP client maps 403 → auth.ErrPartnerInactive.
		writeExtError(w, http.StatusForbidden, "MCP_ADDON_SUSPENDED", "mcp add-on is suspended")
		return
	case err != nil:
		writeExtError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}
	writeExtJSON(w, http.StatusOK, mcpResolveResp{
		AGID:          id.AGID,
		PartnerName:   id.PartnerName,
		TenantID:      id.TenantID,
		AllowedScopes: id.Scopes,
		Active:        id.Active,
	})
}

// -----------------------------------------------------------------------------
// POST /admin/dns/verify
// -----------------------------------------------------------------------------

type dnsVerifyBody struct {
	RegistrationID string `json:"registration_id"`
}

func (r *ExtRouter) dnsVerify(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeExtError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "use POST")
		return
	}
	var body dnsVerifyBody
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeExtError(w, http.StatusBadRequest, "BAD_BODY", err.Error())
		return
	}
	reg, err := r.registrations.Get(body.RegistrationID)
	if errors.Is(err, inmem.ErrNotFound) {
		writeExtError(w, http.StatusNotFound, "REGISTRATION_NOT_FOUND", body.RegistrationID)
		return
	}
	if err != nil {
		writeExtError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}
	if reg.PartnerDomain == "" || reg.DNSVerifyToken == "" {
		writeExtError(w, http.StatusConflict, "DNS_NOT_CONFIGURED",
			"registration did not declare partner_domain at /partners/register")
		return
	}
	verifier := dns.NewVerifier(r.dns)
	res := verifier.Verify(req.Context(), reg.PartnerDomain, reg.DNSVerifyToken)
	tenantID := tenantOrPlatform(req)
	traceparent := req.Header.Get("traceparent")
	if !res.Verified {
		r.publish(events.Event{
			Topic: "chora.a2a.dns_txt.failed.v1",
			Payload: map[string]any{
				"registration_id": reg.ID, "domain": reg.PartnerDomain,
				"reason": res.Reason,
			},
			TenantID:           tenantID,
			Traceparent:        traceparent,
			IMDADimension:      "safety_and_robustness", // D3 — failed verification is a security signal
			IMDALifecycleStage: "runtime",
		})
		writeExtJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"verified": false, "reason": res.Reason,
		})
		return
	}
	reg.DNSVerified = true
	reg.DNSVerifiedAt = &res.At
	_ = r.registrations.Put(reg)
	r.publish(events.Event{
		Topic: "chora.a2a.dns_txt.verified.v1",
		Payload: map[string]any{
			"registration_id": reg.ID, "domain": reg.PartnerDomain,
		},
		TenantID:           tenantID,
		Traceparent:        traceparent,
		IMDADimension:      "accountability",
		IMDALifecycleStage: "runtime",
	})
	writeExtJSON(w, http.StatusOK, map[string]any{
		"verified": true, "verified_at": res.At.Format(time.RFC3339),
	})
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

type extErrorBody struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

func writeExtJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("encode error: %v", err)
	}
}

func writeExtError(w http.ResponseWriter, status int, code, msg string) {
	writeExtJSON(w, status, extErrorBody{Error: msg, Code: code})
}

func toRegistrationResponse(reg *partner.Registration, dnsRecord string) registerRespBody {
	return registerRespBody{
		ID:                 reg.ID,
		OrgName:            reg.OrgName,
		ContactEmail:       reg.ContactEmail,
		Capabilities:       append([]string(nil), reg.Capabilities...),
		RequestedRateLimit: reg.RequestedRateLimit,
		State:              string(reg.State),
		PartnerDomain:      reg.PartnerDomain,
		DNSVerifyToken:     reg.DNSVerifyToken,
		DNSVerifyRecord:    dnsRecord,
		CreatedAt:          reg.CreatedAt.Format(time.RFC3339),
	}
}

func registrationToMap(reg *partner.Registration) map[string]any {
	return map[string]any{
		"id":                   reg.ID,
		"org_name":             reg.OrgName,
		"contact_email":        reg.ContactEmail,
		"capabilities":         reg.Capabilities,
		"requested_rate_limit": reg.RequestedRateLimit,
		"state":                string(reg.State),
		"agid":                 reg.AGID,
		"partner_domain":       reg.PartnerDomain,
		"dns_verified":         reg.DNSVerified,
		"created_at":           reg.CreatedAt.Format(time.RFC3339),
	}
}

func toContractResponse(c *contract.Contract) contractResp {
	caps := make([]map[string]any, 0, len(c.Capabilities))
	for _, x := range c.Capabilities {
		caps = append(caps, map[string]any{
			"name":                  x.Name,
			"tier":                  string(x.Tier),
			"rate_limit_per_minute": x.RateLimitPerMin,
		})
	}
	resp := contractResp{
		ID:           c.ID,
		PartnerID:    c.PartnerID,
		AuthMethod:   string(c.AuthMethod),
		Capabilities: caps,
		Version:      c.Version,
		SupersedesID: c.SupersedesID,
		CreatedAt:    c.CreatedAt.Format(time.RFC3339),
	}
	if c.SunsetAt != nil {
		resp.SunsetAt = c.SunsetAt.Format(time.RFC3339)
	}
	return resp
}

func invocationToMap(i *invocation.Invocation) map[string]any {
	out := map[string]any{
		"id":                  i.ID,
		"agid":                i.AGID,
		"partner_id":          i.PartnerID,
		"capability":          i.Capability,
		"correlation_id":      i.CorrelationID,
		"status":              string(i.Status),
		"latency_ms":          i.LatencyMS,
		"response_size_bytes": i.ResponseSizeBytes,
		"error_code":          i.ErrorCode,
		"started_at":          i.StartedAt.Format(time.RFC3339),
	}
	if i.EndedAt != nil {
		out["ended_at"] = i.EndedAt.Format(time.RFC3339)
	}
	if i.Traceparent != "" {
		out["traceparent"] = i.Traceparent
	}
	// Endpoint is the dispatch URL the gateway routed to. Honest-null
	// contract — omit the key when empty rather than emit a "unknown"
	// placeholder (BFF transformer preserves this — see chora-gateway
	// handlers_oplus.go mapA2AInvocation).
	if i.Endpoint != "" {
		out["endpoint"] = i.Endpoint
	}
	return out
}

func mustNewInvocation(reg *partner.Registration, capability, corr, traceparent string) *invocation.Invocation {
	inv, _ := invocation.New(invocation.NewParams{
		ID:            newUUIDv7(),
		AGID:          reg.AGID,
		PartnerID:     reg.ID,
		Capability:    capability,
		CorrelationID: corr,
		Traceparent:   traceparent,
		Endpoint:      resolveDispatchEndpoint(reg, capability),
	})
	return inv
}

// resolveDispatchEndpoint composes the dispatch URL the gateway routes a
// capability invocation to. Partners that declared a partner_domain at
// /partners/register get a per-partner URL (e.g.
// `https://partner.example/a2a/v1/recommend_content`); otherwise the
// canonical gateway capability URL is used. The "#capability" fragment
// matches the OpenAPI subset rendering at contractOpenAPI() so the O+ A2A
// console can disambiguate per-capability routes inside an aggregated audit
// trail. Empty capability yields empty endpoint (callers MUST never pass an
// "unknown" placeholder downstream).
func resolveDispatchEndpoint(reg *partner.Registration, capability string) string {
	cap := strings.TrimSpace(capability)
	if cap == "" {
		return ""
	}
	if reg != nil && strings.TrimSpace(reg.PartnerDomain) != "" {
		return "https://" + strings.TrimSpace(reg.PartnerDomain) + "/a2a/v1/" + cap
	}
	return "https://a2a.chora.site/a2a/invoke#" + cap
}

func newUUIDv7() string {
	return uuid.Must(uuid.NewV7()).String()
}

func newRandomToken() string {
	u, _ := uuid.NewV7()
	hash := sha256.Sum256([]byte(u.String() + time.Now().UTC().String()))
	return hex.EncodeToString(hash[:])
}

func tenantOrPlatform(r *http.Request) string {
	if v := strings.TrimSpace(r.Header.Get("X-Chora-Tenant-Id")); v != "" {
		return v
	}
	return "platform"
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// verifyKeyHashOnly compares the supplied API key against the persisted
// hash without checking the registration's state — used by the invoke
// handler so that a suspended-but-known-good caller receives 403 instead
// of 401.
func verifyKeyHashOnly(reg *partner.Registration, plaintext string) bool {
	if reg.APIKeyHash == "" {
		return false
	}
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:]) == reg.APIKeyHash
}
