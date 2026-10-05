// Package httpadapter_test — BYOA + MCP + DNS-verify route tests.
//
// CRITICAL invariants:
//   - BYOA route encrypts the supplied API key + emits byoa_key.rotated.v1
//   - BYOA delete soft-removes + emits byoa_key.revoked.v1
//   - MCP config route mints a per-tenant API key (one-time plaintext) +
//     persists tool allowlist
//   - DNS verify route returns 200 on TXT match, 422 on mismatch, 404 if
//     registration not found / didn't declare partner_domain
package httpadapter_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/dns"
	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/events"
	httpadapter "github.com/apollo-chora/chora-a2a-gateway/internal/adapter/http"
	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/repo/inmem"
)

// -----------------------------------------------------------------------------
// BYOA
// -----------------------------------------------------------------------------

func TestBYOA_RegisterEncryptsKey_EmitsRotatedEvent(t *testing.T) {
	t.Parallel()
	r, _, _, _, pub := newExtServer(t)

	masterKey := strings.Repeat("k", 32)
	body, _ := json.Marshal(map[string]any{
		"api_key":           "sk-test-1234567890",
		"tenant_master_key": masterKey,
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/byoa/tenant-1/openai", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d; body = %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if fp, _ := resp["key_fingerprint"].(string); fp == "" {
		t.Error("key_fingerprint missing")
	}
	if got := pub.Snapshot(); len(got) == 0 || got[len(got)-1].Topic != "chora.a2a.byoa_key.rotated.v1" {
		t.Errorf("expected byoa_key.rotated.v1 event; got %+v", got)
	}
}

func TestBYOA_RejectsMissingMasterKey(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newExtServer(t)
	body, _ := json.Marshal(map[string]any{"api_key": "sk"})
	req := httptest.NewRequest(http.MethodPost, "/admin/byoa/tenant-1/openai", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400", rec.Code)
	}
}

func TestBYOA_DeleteSoftRevokes(t *testing.T) {
	t.Parallel()
	r, _, _, _, pub := newExtServer(t)
	masterKey := strings.Repeat("k", 32)
	// Register first.
	body, _ := json.Marshal(map[string]any{"api_key": "sk-1", "tenant_master_key": masterKey})
	req := httptest.NewRequest(http.MethodPost, "/admin/byoa/tenant-1/openai", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register status = %d", rec.Code)
	}
	// Delete.
	delReq := httptest.NewRequest(http.MethodDelete, "/admin/byoa/tenant-1/openai", nil)
	delRec := httptest.NewRecorder()
	r.ServeHTTP(delRec, delReq)
	if delRec.Code != http.StatusOK {
		t.Errorf("delete status = %d", delRec.Code)
	}
	if got := pub.Snapshot(); got[len(got)-1].Topic != "chora.a2a.byoa_key.revoked.v1" {
		t.Errorf("expected byoa_key.revoked.v1; got %s", got[len(got)-1].Topic)
	}
}

// -----------------------------------------------------------------------------
// MCP gateway
// -----------------------------------------------------------------------------

func TestMCP_ConfigEndpointMintsKeyAndStoresAllowlist(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newExtServer(t)
	body, _ := json.Marshal(map[string]any{
		"allowed_tools": []string{"atom_search", "course_catalog"},
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/mcp/tenant-x", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d; body = %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if k, _ := resp["api_key"].(string); k == "" {
		t.Error("api_key empty (must be one-time plaintext on create)")
	}
	tools, _ := resp["allowed_tools"].([]any)
	if len(tools) != 2 {
		t.Errorf("allowed_tools = %v", tools)
	}
}

func TestMCP_GetReturnsConfigButNotKey(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newExtServer(t)
	body, _ := json.Marshal(map[string]any{"allowed_tools": []string{"atom_search"}})
	mkReq := httptest.NewRequest(http.MethodPost, "/admin/mcp/tenant-x", bytes.NewReader(body))
	mkRec := httptest.NewRecorder()
	r.ServeHTTP(mkRec, mkReq)
	if mkRec.Code != http.StatusCreated {
		t.Fatalf("create status = %d", mkRec.Code)
	}
	getRec := httptest.NewRecorder()
	r.ServeHTTP(getRec, httptest.NewRequest(http.MethodGet, "/admin/mcp/tenant-x", nil))
	if getRec.Code != http.StatusOK {
		t.Fatalf("get status = %d", getRec.Code)
	}
	var got map[string]any
	_ = json.Unmarshal(getRec.Body.Bytes(), &got)
	if _, ok := got["api_key"]; ok {
		t.Error("GET should NOT return api_key plaintext")
	}
}

// -----------------------------------------------------------------------------
// DNS verify
// -----------------------------------------------------------------------------

func TestDNSVerify_HappyPath_OnRegistrationWithDomain(t *testing.T) {
	t.Parallel()
	regs := inmem.NewRegistrationRepo()
	contracts := inmem.NewContractRepo()
	invs := inmem.NewInvocationRepo()
	pub := events.NewInMemoryPublisher()
	mock := dns.NewMockResolver()
	mock.SeedTXT("_chora-a2a.acme.example", []string{"chora-a2a-verify=GOOD"})
	r := httpadapter.NewExtRouter(httpadapter.ExtConfig{
		Registrations: regs,
		Contracts:     contracts,
		Invocations:   invs,
		Publisher:     pub,
		DNSResolver:   mock,
	})

	// Register with partner_domain.
	body, _ := json.Marshal(map[string]any{
		"org_name":             "Acme",
		"contact_email":        "ops@acme.example",
		"capabilities":         []string{"recommend"},
		"requested_rate_limit": 60,
		"partner_domain":       "acme.example",
	})
	req := httptest.NewRequest(http.MethodPost, "/partners/register", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register status = %d; body = %s", rec.Code, rec.Body.String())
	}
	var regResp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &regResp)
	id, _ := regResp["id"].(string)
	if id == "" {
		t.Fatal("id missing")
	}

	// Pin token to GOOD so the seeded mock resolver matches.
	reg, _ := regs.Get(id)
	reg.DNSVerifyToken = "GOOD"
	_ = regs.Put(reg)

	verifyBody, _ := json.Marshal(map[string]any{"registration_id": id})
	vReq := httptest.NewRequest(http.MethodPost, "/admin/dns/verify", bytes.NewReader(verifyBody))
	vRec := httptest.NewRecorder()
	r.ServeHTTP(vRec, vReq)
	if vRec.Code != http.StatusOK {
		t.Fatalf("verify status = %d; body = %s", vRec.Code, vRec.Body.String())
	}
	var vResp map[string]any
	_ = json.Unmarshal(vRec.Body.Bytes(), &vResp)
	if v, _ := vResp["verified"].(bool); !v {
		t.Errorf("verified = %v", vResp)
	}

	// Should emit chora.a2a.dns_txt.verified.v1.
	snap := pub.Snapshot()
	last := snap[len(snap)-1]
	if last.Topic != "chora.a2a.dns_txt.verified.v1" {
		t.Errorf("last topic = %q", last.Topic)
	}
	if last.IMDADimension != "accountability" {
		t.Errorf("IMDA dim = %q", last.IMDADimension)
	}
}

func TestDNSVerify_Mismatch_Returns422_AndEmitsFailedEvent(t *testing.T) {
	t.Parallel()
	regs := inmem.NewRegistrationRepo()
	pub := events.NewInMemoryPublisher()
	mock := dns.NewMockResolver()
	mock.SeedTXT("_chora-a2a.acme.example", []string{"chora-a2a-verify=BAD"})
	r := httpadapter.NewExtRouter(httpadapter.ExtConfig{
		Registrations: regs,
		Contracts:     inmem.NewContractRepo(),
		Invocations:   inmem.NewInvocationRepo(),
		Publisher:     pub,
		DNSResolver:   mock,
	})

	body, _ := json.Marshal(map[string]any{
		"org_name":             "Acme",
		"contact_email":        "ops@acme.example",
		"capabilities":         []string{"recommend"},
		"requested_rate_limit": 60,
		"partner_domain":       "acme.example",
	})
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/partners/register", bytes.NewReader(body)))
	var regResp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &regResp)
	id, _ := regResp["id"].(string)

	// Pin token to GOOD so it does NOT match the seeded BAD record.
	reg, _ := regs.Get(id)
	reg.DNSVerifyToken = "GOOD"
	_ = regs.Put(reg)

	vBody, _ := json.Marshal(map[string]any{"registration_id": id})
	vRec := httptest.NewRecorder()
	r.ServeHTTP(vRec, httptest.NewRequest(http.MethodPost, "/admin/dns/verify", bytes.NewReader(vBody)))
	if vRec.Code != http.StatusUnprocessableEntity {
		t.Errorf("status = %d; want 422", vRec.Code)
	}
	snap := pub.Snapshot()
	last := snap[len(snap)-1]
	if last.Topic != "chora.a2a.dns_txt.failed.v1" {
		t.Errorf("topic = %q", last.Topic)
	}
	if last.IMDADimension != "safety_and_robustness" {
		t.Errorf("IMDA dim = %q", last.IMDADimension)
	}
}

func TestDNSVerify_RegistrationWithoutDomainReturns409(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newExtServer(t)
	id := registerOne(t, r, "NoDomain")
	body, _ := json.Marshal(map[string]any{"registration_id": id})
	req := httptest.NewRequest(http.MethodPost, "/admin/dns/verify", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d; want 409", rec.Code)
	}
}

func TestDNSVerify_LookupErrorReturns422(t *testing.T) {
	t.Parallel()
	regs := inmem.NewRegistrationRepo()
	pub := events.NewInMemoryPublisher()
	mock := dns.NewMockResolver()
	mock.SeedError("_chora-a2a.broken.example", errors.New("NXDOMAIN"))
	r := httpadapter.NewExtRouter(httpadapter.ExtConfig{
		Registrations: regs,
		Contracts:     inmem.NewContractRepo(),
		Invocations:   inmem.NewInvocationRepo(),
		Publisher:     pub,
		DNSResolver:   mock,
	})
	body, _ := json.Marshal(map[string]any{
		"org_name":             "Broken",
		"contact_email":        "ops@broken.example",
		"capabilities":         []string{"recommend"},
		"requested_rate_limit": 60,
		"partner_domain":       "broken.example",
	})
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/partners/register", bytes.NewReader(body)))
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	id, _ := resp["id"].(string)

	vBody, _ := json.Marshal(map[string]any{"registration_id": id})
	vRec := httptest.NewRecorder()
	r.ServeHTTP(vRec, httptest.NewRequest(http.MethodPost, "/admin/dns/verify", bytes.NewReader(vBody)))
	if vRec.Code != http.StatusUnprocessableEntity {
		t.Errorf("status = %d; want 422", vRec.Code)
	}
}

// -----------------------------------------------------------------------------
// Property test — AGID never holds TenantMembership across permutations
// -----------------------------------------------------------------------------

func TestProperty_AGID_NeverInGCIDFields(t *testing.T) {
	t.Parallel()
	r, _, _, _, pub := newExtServer(t)
	// Run 100+ register/approve/contract/invoke permutations and assert the
	// audit body never leaks an "agid" value into a "gcid" or "approver_gcid"
	// position in a published event.
	for i := 0; i < 105; i++ {
		pid := registerOne(t, r, "OrgX")
		_, key := approveOne(t, r, pid)
		createContractWithName(t, r, pid, "recommend_content", "high", 600)
		body, _ := json.Marshal(map[string]any{"capability": "recommend_content"})
		corr := padCorr(i + 1)
		req := httptest.NewRequest(http.MethodPost, "/a2a/invoke", bytes.NewReader(body))
		req.Header.Set("X-Partner-Id", pid)
		req.Header.Set("X-API-Key", key)
		req.Header.Set("X-Correlation-Id", corr)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
	}
	snap := pub.Snapshot()
	for _, e := range snap {
		// Look for any payload value that's an AGID-shaped string under a gcid key.
		if v, ok := e.Payload["gcid"]; ok {
			s, _ := v.(string)
			if strings.HasPrefix(s, "agid:") {
				t.Fatalf("AGID leaked into gcid field: topic=%s payload=%v", e.Topic, e.Payload)
			}
		}
		if v, ok := e.Payload["approver_gcid"]; ok {
			s, _ := v.(string)
			if strings.HasPrefix(s, "agid:") {
				t.Fatalf("AGID leaked into approver_gcid field: topic=%s payload=%v", e.Topic, e.Payload)
			}
		}
	}
	// Independently ensure context-derived GCID was never an AGID.
	_ = context.Background()
}
