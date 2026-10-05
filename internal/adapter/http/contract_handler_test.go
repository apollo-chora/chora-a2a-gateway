// Package httpadapter_test — contract handlers (task spec §2: routes 6-7).
//
// Routes under test:
//
//	POST /contracts/{partner_id}              register agent contract
//	GET  /contracts/{partner_id}              list partner contracts
//
// TDD RED phase — implementation does NOT yet exist.
package httpadapter_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// -----------------------------------------------------------------------------
// POST /contracts/{partner_id}
// -----------------------------------------------------------------------------

func TestRegisterContract_RequiresApprovedPartner(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newExtServer(t)
	pid := registerOne(t, r, "Pending Inc") // pending, NOT approved

	body, _ := json.Marshal(map[string]any{
		"auth_method": "api_key",
		"capabilities": []map[string]any{
			{"name": "recommend_content", "tier": "medium", "rate_limit_per_minute": 60},
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/contracts/"+pid, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d; want 409 (partner not approved)", rec.Code)
	}
}

func TestRegisterContract_HappyPath(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newExtServer(t)
	pid := registerOne(t, r, "Acme")
	approveOne(t, r, pid)

	body, _ := json.Marshal(map[string]any{
		"auth_method": "api_key",
		"capabilities": []map[string]any{
			{"name": "recommend_content", "tier": "medium", "rate_limit_per_minute": 60},
			{"name": "discover_learner_profile", "tier": "low", "rate_limit_per_minute": 30},
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/contracts/"+pid, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d; body = %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if id, _ := resp["id"].(string); id == "" {
		t.Error("contract id empty")
	}
	caps, _ := resp["capabilities"].([]any)
	if len(caps) != 2 {
		t.Errorf("capabilities len = %d; want 2", len(caps))
	}
}

func TestRegisterContract_RejectsBadAuthMethod(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newExtServer(t)
	pid := registerOne(t, r, "Acme")
	approveOne(t, r, pid)

	body, _ := json.Marshal(map[string]any{
		"auth_method": "bogus",
		"capabilities": []map[string]any{
			{"name": "x", "tier": "low", "rate_limit_per_minute": 10},
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/contracts/"+pid, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400", rec.Code)
	}
}

// -----------------------------------------------------------------------------
// GET /contracts/{partner_id}
// -----------------------------------------------------------------------------

func TestListContracts_HappyPath(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newExtServer(t)
	pid := registerOne(t, r, "Acme")
	approveOne(t, r, pid)
	createContract(t, r, pid, "low", 30)
	createContract(t, r, pid, "medium", 60)

	req := httptest.NewRequest(http.MethodGet, "/contracts/"+pid, nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var resp struct {
		Contracts []map[string]any `json:"contracts"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Contracts) != 2 {
		t.Errorf("contracts len = %d; want 2", len(resp.Contracts))
	}
}

func TestListContracts_PartnerNotFound(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newExtServer(t)
	req := httptest.NewRequest(http.MethodGet, "/contracts/01970000-0000-0000-0000-000000000000", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d; want 404", rec.Code)
	}
}

// createContract is a test helper that creates one contract for a partner.
func createContract(t *testing.T, r interface {
	ServeHTTP(http.ResponseWriter, *http.Request)
}, pid, tier string, rate int) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"auth_method": "api_key",
		"capabilities": []map[string]any{
			{"name": "cap_" + tier, "tier": tier, "rate_limit_per_minute": rate},
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/contracts/"+pid, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("createContract status = %d; body = %s", rec.Code, rec.Body.String())
	}
}
