// Package httpadapter_test — mcp_resolve_test.go: POST /admin/mcp/_resolve,
// the server side of the contract chora-mcp-gateway's A2AClient already calls
// (clients/a2a_client.go resolverResponse). The wire shape MUST match verbatim
// so the existing client works unchanged:
//
//	request : POST /admin/mcp/_resolve, X-API-Key: <plaintext>, no body
//	response: {agid, partner_name, tenant_id, allowed_scopes, active}
//	          200 on a live key; 401 (no identity body) on unknown/revoked;
//	          400 on an empty key.
//
// Gating: _resolve lives under the internal-only /admin/mcp/* prefix exactly
// like the sibling config routes — it is NOT on the public partner API Gateway
// surface (a2a.chora.site exposes only /a2a/* + /api/v1/a2a/*). The credential
// IS the resolved key, so there is no separate admin token (the MCP client
// sends only X-API-Key).
package httpadapter_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/events"
	httpadapter "github.com/apollo-chora/chora-a2a-gateway/internal/adapter/http"
	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/repo/inmem"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/partner"
)

// resolverResponse mirrors chora-mcp-gateway's clients.resolverResponse (the
// pinned wire contract). Field tags/casing MUST stay identical.
type resolverResponse struct {
	AGID          string   `json:"agid"`
	PartnerName   string   `json:"partner_name"`
	TenantID      string   `json:"tenant_id"`
	AllowedScopes []string `json:"allowed_scopes"`
	Active        bool     `json:"active"`
}

// provisionMCP provisions a per-tenant MCP add-on via the admin config route
// and returns the one-time plaintext key.
func provisionMCP(t *testing.T, r *httpadapter.ExtRouter, tenantID string, tools []string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"allowed_tools": tools})
	req := httptest.NewRequest(http.MethodPost, "/admin/mcp/"+tenantID, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("provision status = %d; body = %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	key, _ := resp["api_key"].(string)
	if key == "" {
		t.Fatal("provision returned empty api_key")
	}
	return key
}

func TestMCPResolve_ValidKey_Returns200WithIdentity(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newExtServer(t)
	key := provisionMCP(t, r, "tenant-x", []string{"atom_search", "course_catalog"})

	req := httptest.NewRequest(http.MethodPost, "/admin/mcp/_resolve", nil)
	req.Header.Set("X-API-Key", key)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body = %s", rec.Code, rec.Body.String())
	}
	var resp resolverResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v; body=%s", err, rec.Body.String())
	}
	if resp.TenantID != "tenant-x" {
		t.Errorf("tenant_id = %q; want tenant-x", resp.TenantID)
	}
	if resp.AGID != "agid:tenant-x:mcp:01" {
		t.Errorf("agid = %q; want agid:tenant-x:mcp:01", resp.AGID)
	}
	if !resp.Active {
		t.Error("active = false; want true for a live key")
	}
	if len(resp.AllowedScopes) != 2 {
		t.Errorf("allowed_scopes = %v; want 2 tools", resp.AllowedScopes)
	}
	if resp.PartnerName == "" {
		t.Error("partner_name empty; want a display label")
	}
}

func TestMCPResolve_UnknownKey_Returns401_NoIdentityBody(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newExtServer(t)
	_ = provisionMCP(t, r, "tenant-x", []string{"atom_search"}) // non-empty repo

	req := httptest.NewRequest(http.MethodPost, "/admin/mcp/_resolve", nil)
	req.Header.Set("X-API-Key", "not-a-real-key")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d; want 401; body=%s", rec.Code, rec.Body.String())
	}
	// Fail loud: a rejection MUST NOT leak any identity field.
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	for _, leak := range []string{"agid", "tenant_id", "allowed_scopes", "partner_name"} {
		if _, ok := body[leak]; ok {
			t.Errorf("401 body leaked identity field %q: %v", leak, body)
		}
	}
}

func TestMCPResolve_EmptyKey_Returns400(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newExtServer(t)
	req := httptest.NewRequest(http.MethodPost, "/admin/mcp/_resolve", nil) // no X-API-Key
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestMCPResolve_WrongMethod_Returns405(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newExtServer(t)
	req := httptest.NewRequest(http.MethodGet, "/admin/mcp/_resolve", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d; want 405", rec.Code)
	}
}

func TestMCPResolve_DoesNotShadowConfigRoute(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newExtServer(t)
	// GET /admin/mcp/{tenant} must still reach the config route (404 for an
	// unknown tenant), proving the exact _resolve pattern did not swallow the
	// /admin/mcp/ subtree.
	req := httptest.NewRequest(http.MethodGet, "/admin/mcp/some-tenant", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET /admin/mcp/some-tenant status = %d; want 404 (config route, not _resolve)", rec.Code)
	}
}

func TestMCPResolve_RevokedAddOn_Returns401(t *testing.T) {
	t.Parallel()
	mcpRepo := inmem.NewMCPConfigRepo()
	r := httpadapter.NewExtRouter(httpadapter.ExtConfig{
		Registrations: inmem.NewRegistrationRepo(),
		Contracts:     inmem.NewContractRepo(),
		Invocations:   inmem.NewInvocationRepo(),
		Publisher:     events.NewInMemoryPublisher(),
		MCPConfigs:    mcpRepo,
	})
	key := provisionMCP(t, r, "tenant-del", []string{"atom_search"})

	// Revoke (soft-delete) the add-on directly in the repo.
	cfg, err := mcpRepo.Get("tenant-del")
	if err != nil {
		t.Fatalf("get cfg: %v", err)
	}
	now := time.Now().UTC()
	cfg.DeletedAt = &now
	_ = mcpRepo.Put(cfg)

	req := httptest.NewRequest(http.MethodPost, "/admin/mcp/_resolve", nil)
	req.Header.Set("X-API-Key", key)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("revoked add-on resolve status = %d; want 401", rec.Code)
	}
}

func TestMCPResolve_SuspendedAddOn_Returns403_NoIdentityBody(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newExtServer(t)
	key := provisionMCP(t, r, "tenant-susp", []string{"atom_search"})

	suspendReq := httptest.NewRequest(http.MethodPost, "/admin/mcp/tenant-susp:suspend", nil)
	suspendRec := httptest.NewRecorder()
	r.ServeHTTP(suspendRec, suspendReq)
	if suspendRec.Code != http.StatusOK {
		t.Fatalf("suspend status = %d; body = %s", suspendRec.Code, suspendRec.Body.String())
	}

	req := httptest.NewRequest(http.MethodPost, "/admin/mcp/_resolve", nil)
	req.Header.Set("X-API-Key", key)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("resolve status after suspend = %d; want 403; body=%s", rec.Code, rec.Body.String())
	}
	// Fail loud: a 403 rejection MUST NOT leak any identity field either.
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	for _, leak := range []string{"agid", "tenant_id", "allowed_scopes", "partner_name"} {
		if _, ok := body[leak]; ok {
			t.Errorf("403 body leaked identity field %q: %v", leak, body)
		}
	}
}

func TestMCPResolve_ReinstatedAddOn_Returns200Again(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newExtServer(t)
	key := provisionMCP(t, r, "tenant-re", []string{"atom_search"})

	post := func(path string) int {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := post("/admin/mcp/tenant-re:suspend"); code != http.StatusOK {
		t.Fatalf("suspend status = %d", code)
	}
	if code := post("/admin/mcp/tenant-re:reinstate"); code != http.StatusOK {
		t.Fatalf("reinstate status = %d", code)
	}

	req := httptest.NewRequest(http.MethodPost, "/admin/mcp/_resolve", nil)
	req.Header.Set("X-API-Key", key)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("resolve status after reinstate = %d; want 200; body=%s", rec.Code, rec.Body.String())
	}
}

// -----------------------------------------------------------------------------
// POST /admin/mcp/{tenant_id}:suspend | :reinstate
// -----------------------------------------------------------------------------

func TestMCPConfigOp_UnknownTenant_Returns404(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newExtServer(t)
	req := httptest.NewRequest(http.MethodPost, "/admin/mcp/no-such-tenant:suspend", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d; want 404", rec.Code)
	}
}

func TestMCPConfigOp_UnknownOp_Returns400(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newExtServer(t)
	_ = provisionMCP(t, r, "tenant-x", []string{"atom_search"})
	req := httptest.NewRequest(http.MethodPost, "/admin/mcp/tenant-x:frobnicate", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400", rec.Code)
	}
}

func TestMCPConfigOp_WrongMethod_Returns405(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newExtServer(t)
	_ = provisionMCP(t, r, "tenant-x", []string{"atom_search"})
	req := httptest.NewRequest(http.MethodGet, "/admin/mcp/tenant-x:suspend", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d; want 405", rec.Code)
	}
}

func TestMCPConfigSuspend_EmitsEvent(t *testing.T) {
	t.Parallel()
	r, _, _, _, pub := newExtServer(t)
	_ = provisionMCP(t, r, "tenant-evt", []string{"atom_search"})
	req := httptest.NewRequest(http.MethodPost, "/admin/mcp/tenant-evt:suspend", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body = %s", rec.Code, rec.Body.String())
	}
	snap := pub.Snapshot()
	if len(snap) == 0 || snap[len(snap)-1].Topic != "chora.a2a.mcp_addon.suspended.v1" {
		t.Fatalf("events = %+v; want last topic chora.a2a.mcp_addon.suspended.v1", snap)
	}
}

func TestMCPConfigGet_ExposesSuspendedFlag(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newExtServer(t)
	_ = provisionMCP(t, r, "tenant-flag", []string{"atom_search"})

	suspendReq := httptest.NewRequest(http.MethodPost, "/admin/mcp/tenant-flag:suspend", nil)
	suspendRec := httptest.NewRecorder()
	r.ServeHTTP(suspendRec, suspendReq)
	if suspendRec.Code != http.StatusOK {
		t.Fatalf("suspend status = %d", suspendRec.Code)
	}

	getReq := httptest.NewRequest(http.MethodGet, "/admin/mcp/tenant-flag", nil)
	getRec := httptest.NewRecorder()
	r.ServeHTTP(getRec, getReq)
	var got map[string]any
	_ = json.Unmarshal(getRec.Body.Bytes(), &got)
	if suspended, _ := got["suspended"].(bool); !suspended {
		t.Errorf("GET config suspended = %v; want true after :suspend", got["suspended"])
	}
}

func TestMCPResolve_TenantlessAddOn_Returns500_NoIdentity(t *testing.T) {
	t.Parallel()
	// A corrupt add-on row with a blank tenant must fail loud (500) and never
	// emit a tenant-less identity. Seed it directly (the config route can never
	// create one — the tenant comes from the URL path).
	mcpRepo := inmem.NewMCPConfigRepo()
	const plaintext = "raw-mcp-key-no-tenant"
	_ = mcpRepo.Put(&inmem.MCPConfig{
		TenantID:     "", // corrupt / impossible via the config route
		APIKeyHash:   partner.HashAPIKey(plaintext),
		AllowedTools: []string{"atom_search"},
	})
	r := httpadapter.NewExtRouter(httpadapter.ExtConfig{
		Registrations: inmem.NewRegistrationRepo(),
		Contracts:     inmem.NewContractRepo(),
		Invocations:   inmem.NewInvocationRepo(),
		Publisher:     events.NewInMemoryPublisher(),
		MCPConfigs:    mcpRepo,
	})

	req := httptest.NewRequest(http.MethodPost, "/admin/mcp/_resolve", nil)
	req.Header.Set("X-API-Key", plaintext)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d; want 500 (fail loud on tenant-less add-on)", rec.Code)
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	for _, leak := range []string{"agid", "tenant_id", "allowed_scopes", "partner_name", "active"} {
		if _, ok := body[leak]; ok {
			t.Errorf("500 body leaked identity field %q: %v", leak, body)
		}
	}
}
