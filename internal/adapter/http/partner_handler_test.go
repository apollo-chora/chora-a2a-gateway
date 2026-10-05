// Package httpadapter_test — partner registration handlers (task spec §1).
//
// Routes under test:
//
//	POST /partners/register                    public submit
//	GET  /partners/{id}                        partner detail
//	POST /admin/partners/{id}:approve          admin approve (mints AGID + key)
//	POST /admin/partners/{id}:suspend          admin suspend
//	GET  /admin/partners?status=X              admin queue
//
// Tests for DDD-compliance + state-machine correctness.
//
// TDD RED phase — implementation does NOT yet exist.
package httpadapter_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/events"
	httpadapter "github.com/apollo-chora/chora-a2a-gateway/internal/adapter/http"
	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/repo/inmem"
)

func newExtServer(t *testing.T) (*httpadapter.ExtRouter, *inmem.RegistrationRepo, *inmem.ContractRepo, *inmem.InvocationRepo, *events.InMemoryPublisher) {
	t.Helper()
	regs := inmem.NewRegistrationRepo()
	cons := inmem.NewContractRepo()
	invs := inmem.NewInvocationRepo()
	pub := events.NewInMemoryPublisher()
	r := httpadapter.NewExtRouter(httpadapter.ExtConfig{
		Registrations: regs,
		Contracts:     cons,
		Invocations:   invs,
		Publisher:     pub,
	})
	return r, regs, cons, invs, pub
}

// -----------------------------------------------------------------------------
// POST /partners/register
// -----------------------------------------------------------------------------

func TestPartnersRegister_HappyPath(t *testing.T) {
	t.Parallel()
	r, regs, _, _, pub := newExtServer(t)

	body, _ := json.Marshal(map[string]any{
		"org_name":             "Acme Tutor Co",
		"contact_email":        "ops@acme.example",
		"capabilities":         []string{"recommend_content"},
		"requested_rate_limit": 100,
	})
	req := httptest.NewRequest(http.MethodPost, "/partners/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d; body = %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	id, _ := resp["id"].(string)
	if id == "" {
		t.Fatal("id missing in response")
	}
	if got, _ := resp["state"].(string); got != "pending" {
		t.Errorf("state = %q; want pending", got)
	}
	if _, err := regs.Get(id); err != nil {
		t.Errorf("registration not persisted: %v", err)
	}
	snap := pub.Snapshot()
	if len(snap) != 1 || snap[0].Topic != "chora.a2a.partner.registered.v1" {
		t.Errorf("expected partner.registered.v1 event; got %+v", snap)
	}
}

func TestPartnersRegister_MissingFields(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newExtServer(t)

	body, _ := json.Marshal(map[string]any{
		"org_name": "Acme",
		// missing contact_email + capabilities + rate limit
	})
	req := httptest.NewRequest(http.MethodPost, "/partners/register", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400", rec.Code)
	}
}

// -----------------------------------------------------------------------------
// GET /partners/{id}
// -----------------------------------------------------------------------------

func TestPartnerDetail_HappyPath(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newExtServer(t)

	id := registerOne(t, r, "Acme")

	req := httptest.NewRequest(http.MethodGet, "/partners/"+id, nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if got, _ := resp["org_name"].(string); got != "Acme" {
		t.Errorf("org_name = %q", got)
	}
}

func TestPartnerDetail_NotFound(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newExtServer(t)
	req := httptest.NewRequest(http.MethodGet, "/partners/01970000-0000-0000-0000-000000000000", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d; want 404", rec.Code)
	}
}

// -----------------------------------------------------------------------------
// POST /admin/partners/{id}:approve
// -----------------------------------------------------------------------------

func TestPartnerApprove_MintsAGIDAndAPIKey(t *testing.T) {
	t.Parallel()
	r, regs, _, _, pub := newExtServer(t)

	id := registerOne(t, r, "Acme")

	approveBody, _ := json.Marshal(map[string]any{
		"approver_gcid": "01970000-0000-7000-9000-000000000001",
		"tier":          "medium",
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/partners/"+id+":approve", bytes.NewReader(approveBody))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body = %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if got, _ := resp["state"].(string); got != "approved" {
		t.Errorf("state = %q", got)
	}
	if got, _ := resp["agid"].(string); got == "" {
		t.Error("AGID missing in approval response")
	}
	if got, _ := resp["api_key"].(string); got == "" {
		t.Error("api_key missing — required one-time plaintext on approval")
	}
	persisted, _ := regs.Get(id)
	if persisted.APIKeyHash == "" {
		t.Error("APIKeyHash not persisted")
	}
	// One registered + one approved event expected.
	snap := pub.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("expected 2 events; got %d", len(snap))
	}
	if snap[1].Topic != "chora.a2a.partner.approved.v1" {
		t.Errorf("topic = %q; want chora.a2a.partner.approved.v1", snap[1].Topic)
	}
}

func TestPartnerApprove_RejectsDoubleApproval(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newExtServer(t)

	id := registerOne(t, r, "Acme")
	body, _ := json.Marshal(map[string]any{
		"approver_gcid": "01970000-0000-7000-9000-000000000001",
		"tier":          "low",
	})
	// First approval ok.
	req := httptest.NewRequest(http.MethodPost, "/admin/partners/"+id+":approve", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("first approve status = %d; want 200", rec.Code)
	}
	// Second approval rejected with 409 (state-machine violation).
	req2 := httptest.NewRequest(http.MethodPost, "/admin/partners/"+id+":approve", bytes.NewReader(body))
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusConflict {
		t.Errorf("second approve status = %d; want 409", rec2.Code)
	}
}

func TestPartnerApprove_NotFound(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newExtServer(t)
	body, _ := json.Marshal(map[string]any{"approver_gcid": "x", "tier": "low"})
	req := httptest.NewRequest(http.MethodPost, "/admin/partners/01970000-0000-7000-a000-99999999:approve", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d; want 404", rec.Code)
	}
}

// -----------------------------------------------------------------------------
// POST /admin/partners/{id}:suspend
// -----------------------------------------------------------------------------

func TestPartnerSuspend_HappyPath(t *testing.T) {
	t.Parallel()
	r, _, _, _, pub := newExtServer(t)
	id := registerOne(t, r, "Acme")
	approveOne(t, r, id)

	body, _ := json.Marshal(map[string]any{
		"approver_gcid": "01970000-0000-7000-9000-000000000001",
		"reason":        "policy_violation",
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/partners/"+id+":suspend", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body = %s", rec.Code, rec.Body.String())
	}

	// 3 events: registered, approved, suspended.
	snap := pub.Snapshot()
	if len(snap) != 3 {
		t.Fatalf("expected 3 events, got %d", len(snap))
	}
	if snap[2].Topic != "chora.a2a.partner.suspended.v1" {
		t.Errorf("topic = %q", snap[2].Topic)
	}
}

func TestPartnerSuspend_RejectsPending(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newExtServer(t)
	id := registerOne(t, r, "Acme") // not approved
	body, _ := json.Marshal(map[string]any{
		"approver_gcid": "01970000-0000-7000-9000-000000000001",
		"reason":        "x",
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/partners/"+id+":suspend", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d; want 409 (state-machine)", rec.Code)
	}
}

// -----------------------------------------------------------------------------
// GET /admin/partners?status=X
// -----------------------------------------------------------------------------

func TestAdminPartnerQueue_FiltersByStatus(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newExtServer(t)
	pendID := registerOne(t, r, "Pending Inc")
	approvedID := registerOne(t, r, "Approved Inc")
	approveOne(t, r, approvedID)

	// pending list
	req := httptest.NewRequest(http.MethodGet, "/admin/partners?status=pending", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var p struct {
		Partners []map[string]any `json:"partners"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &p)
	if len(p.Partners) != 1 {
		t.Fatalf("pending list len = %d; want 1", len(p.Partners))
	}
	if got, _ := p.Partners[0]["id"].(string); got != pendID {
		t.Errorf("pending list id = %q; want %q", got, pendID)
	}

	// approved list
	req2 := httptest.NewRequest(http.MethodGet, "/admin/partners?status=approved", nil)
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, req2)
	var p2 struct {
		Partners []map[string]any `json:"partners"`
	}
	_ = json.Unmarshal(rec2.Body.Bytes(), &p2)
	if len(p2.Partners) != 1 {
		t.Fatalf("approved list len = %d; want 1", len(p2.Partners))
	}
	if got, _ := p2.Partners[0]["id"].(string); got != approvedID {
		t.Errorf("approved id = %q; want %q", got, approvedID)
	}
}

func TestAdminPartnerQueue_RejectsInvalidStatus(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newExtServer(t)
	req := httptest.NewRequest(http.MethodGet, "/admin/partners?status=bogus", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400", rec.Code)
	}
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

// registerOne creates a partner and returns the new id.
func registerOne(t *testing.T, r *httpadapter.ExtRouter, org string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"org_name":             org,
		"contact_email":        "ops@" + sanitizedDomain(org) + ".example",
		"capabilities":         []string{"recommend_content"},
		"requested_rate_limit": 60,
	})
	req := httptest.NewRequest(http.MethodPost, "/partners/register", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("registerOne status = %d; body = %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	id, _ := resp["id"].(string)
	if id == "" {
		t.Fatal("registerOne id empty")
	}
	return id
}

// approveOne approves a registration; returns the AGID and api_key.
func approveOne(t *testing.T, r *httpadapter.ExtRouter, id string) (string, string) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"approver_gcid": "01970000-0000-7000-9000-000000000001",
		"tier":          "low",
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/partners/"+id+":approve", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("approveOne status = %d; body = %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	agid, _ := resp["agid"].(string)
	key, _ := resp["api_key"].(string)
	return agid, key
}

func sanitizedDomain(org string) string {
	// Tiny helper for synthetic emails.
	out := make([]byte, 0, len(org))
	for i := 0; i < len(org); i++ {
		c := org[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return "example"
	}
	return string(out)
}
