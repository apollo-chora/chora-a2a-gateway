// Package httpadapter_test — invocation handlers (task spec §2: routes 8-9).
//
// Routes under test:
//
//	POST /a2a/invoke               partner-facing endpoint
//	GET  /a2a/audit?partner_id=X   audit trail of A2A invocations
//
// Tests:
//   - validate contract (capability not in list → 403)
//   - rate-limit (per-AGID; exceed → 429 with Retry-After header)
//   - audit row written for every invoke
//   - audit endpoint returns rows for a partner
//
// TDD RED phase — implementation does NOT yet exist.
package httpadapter_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestA2AInvoke_HappyPath(t *testing.T) {
	t.Parallel()
	r, _, _, _, pub := newExtServer(t)
	pid := registerOne(t, r, "Acme")
	_, key := approveOne(t, r, pid)
	createContractWithName(t, r, pid, "recommend_content", "medium", 600)

	body, _ := json.Marshal(map[string]any{
		"capability": "recommend_content",
		"params":     map[string]any{"k": "v"},
	})
	req := httptest.NewRequest(http.MethodPost, "/a2a/invoke", bytes.NewReader(body))
	req.Header.Set("X-Partner-Id", pid)
	req.Header.Set("X-API-Key", key)
	req.Header.Set("X-Correlation-Id", "01970000-0000-7000-c000-000000000001")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body = %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if got, _ := resp["status"].(string); got != "completed" {
		t.Errorf("status = %q; want completed", got)
	}
	// Snapshot: registered + approved + invocation_completed.
	snap := pub.Snapshot()
	if len(snap) < 3 {
		t.Fatalf("expected >=3 events; got %d", len(snap))
	}
	last := snap[len(snap)-1]
	if last.Topic != "chora.a2a.invocation.completed.v1" {
		t.Errorf("last topic = %q", last.Topic)
	}
}

func TestA2AInvoke_CapabilityNotInContract(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newExtServer(t)
	pid := registerOne(t, r, "Acme")
	_, key := approveOne(t, r, pid)
	createContractWithName(t, r, pid, "recommend_content", "low", 60)

	body, _ := json.Marshal(map[string]any{
		"capability": "write_persona_memory",
	})
	req := httptest.NewRequest(http.MethodPost, "/a2a/invoke", bytes.NewReader(body))
	req.Header.Set("X-Partner-Id", pid)
	req.Header.Set("X-API-Key", key)
	req.Header.Set("X-Correlation-Id", "01970000-0000-7000-c000-000000000099")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d; want 403", rec.Code)
	}
}

func TestA2AInvoke_RateLimitExceeded(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newExtServer(t)
	pid := registerOne(t, r, "Acme")
	_, key := approveOne(t, r, pid)
	// Tiny rate limit so we can exhaust.
	createContractWithName(t, r, pid, "recommend_content", "low", 1)

	body, _ := json.Marshal(map[string]any{"capability": "recommend_content"})
	mkReq := func(corr string) *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/a2a/invoke", bytes.NewReader(body))
		req.Header.Set("X-Partner-Id", pid)
		req.Header.Set("X-API-Key", key)
		req.Header.Set("X-Correlation-Id", corr)
		return req
	}

	// First should succeed (burst=1).
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, mkReq("01970000-0000-7000-c000-000000000001"))
	if rec.Code != http.StatusOK {
		t.Fatalf("first call status = %d; body = %s", rec.Code, rec.Body.String())
	}

	// Second should be rate-limited.
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, mkReq("01970000-0000-7000-c000-000000000002"))
	if rec2.Code != http.StatusTooManyRequests {
		t.Errorf("second call status = %d; want 429", rec2.Code)
	}
	if got := rec2.Header().Get("Retry-After"); got == "" {
		t.Error("missing Retry-After on 429")
	}
}

func TestA2AInvoke_RejectsMissingAPIKey(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newExtServer(t)
	pid := registerOne(t, r, "Acme")
	approveOne(t, r, pid)
	createContractWithName(t, r, pid, "recommend_content", "low", 60)

	body, _ := json.Marshal(map[string]any{"capability": "recommend_content"})
	req := httptest.NewRequest(http.MethodPost, "/a2a/invoke", bytes.NewReader(body))
	req.Header.Set("X-Partner-Id", pid)
	req.Header.Set("X-Correlation-Id", "01970000-0000-7000-c000-000000000033")
	// no X-API-Key
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d; want 401", rec.Code)
	}
}

func TestA2AInvoke_RejectsBadAPIKey(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newExtServer(t)
	pid := registerOne(t, r, "Acme")
	approveOne(t, r, pid)
	createContractWithName(t, r, pid, "recommend_content", "low", 60)

	body, _ := json.Marshal(map[string]any{"capability": "recommend_content"})
	req := httptest.NewRequest(http.MethodPost, "/a2a/invoke", bytes.NewReader(body))
	req.Header.Set("X-Partner-Id", pid)
	req.Header.Set("X-API-Key", "incorrect-key")
	req.Header.Set("X-Correlation-Id", "01970000-0000-7000-c000-000000000034")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d; want 401", rec.Code)
	}
}

func TestA2AInvoke_RejectsSuspendedPartner(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newExtServer(t)
	pid := registerOne(t, r, "Acme")
	_, key := approveOne(t, r, pid)
	createContractWithName(t, r, pid, "recommend_content", "low", 60)

	// Suspend
	suspendBody, _ := json.Marshal(map[string]any{
		"approver_gcid": "01970000-0000-7000-9000-000000000001",
		"reason":        "compliance_review",
	})
	suspReq := httptest.NewRequest(http.MethodPost, "/admin/partners/"+pid+":suspend", bytes.NewReader(suspendBody))
	suspRec := httptest.NewRecorder()
	r.ServeHTTP(suspRec, suspReq)

	body, _ := json.Marshal(map[string]any{"capability": "recommend_content"})
	req := httptest.NewRequest(http.MethodPost, "/a2a/invoke", bytes.NewReader(body))
	req.Header.Set("X-Partner-Id", pid)
	req.Header.Set("X-API-Key", key)
	req.Header.Set("X-Correlation-Id", "01970000-0000-7000-c000-000000000044")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d; want 403 (suspended)", rec.Code)
	}
}

// -----------------------------------------------------------------------------
// GET /a2a/audit?partner_id=X
// -----------------------------------------------------------------------------

func TestA2AAudit_HappyPath(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newExtServer(t)
	pid := registerOne(t, r, "Acme")
	_, key := approveOne(t, r, pid)
	createContractWithName(t, r, pid, "recommend_content", "high", 600)

	// Make 2 invocations.
	for i := 1; i <= 2; i++ {
		body, _ := json.Marshal(map[string]any{"capability": "recommend_content"})
		req := httptest.NewRequest(http.MethodPost, "/a2a/invoke", bytes.NewReader(body))
		req.Header.Set("X-Partner-Id", pid)
		req.Header.Set("X-API-Key", key)
		req.Header.Set("X-Correlation-Id", padCorr(i))
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("invoke %d status = %d; body = %s", i, rec.Code, rec.Body.String())
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/a2a/audit?partner_id="+pid, nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("audit status = %d", rec.Code)
	}
	var resp struct {
		Invocations []map[string]any `json:"invocations"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Invocations) != 2 {
		t.Errorf("audit list len = %d; want 2", len(resp.Invocations))
	}

	// Audit MUST NOT expose any "gcid" key.
	body, _ := json.Marshal(resp)
	if strings.Contains(strings.ToLower(string(body)), "gcid") {
		t.Errorf("audit body leaks 'gcid' key: %s", string(body))
	}
}

func TestA2AAudit_RequiresPartnerID(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newExtServer(t)
	req := httptest.NewRequest(http.MethodGet, "/a2a/audit", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400", rec.Code)
	}
}

// Audit MUST record the dispatch endpoint URL on each invocation row — the
// O+ A2A console derives the displayed endpoint from this field directly
// (no fallback placeholder).
func TestA2AAudit_RecordsDispatchEndpoint(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newExtServer(t)
	pid := registerOne(t, r, "Acme")
	_, key := approveOne(t, r, pid)
	createContractWithName(t, r, pid, "recommend_content", "high", 600)

	body, _ := json.Marshal(map[string]any{"capability": "recommend_content"})
	req := httptest.NewRequest(http.MethodPost, "/a2a/invoke", bytes.NewReader(body))
	req.Header.Set("X-Partner-Id", pid)
	req.Header.Set("X-API-Key", key)
	req.Header.Set("X-Correlation-Id", "01970000-0000-7000-c000-000000000777")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("invoke status = %d; body = %s", rec.Code, rec.Body.String())
	}

	auditReq := httptest.NewRequest(http.MethodGet, "/a2a/audit?partner_id="+pid, nil)
	auditRec := httptest.NewRecorder()
	r.ServeHTTP(auditRec, auditReq)
	var resp struct {
		Invocations []map[string]any `json:"invocations"`
	}
	_ = json.Unmarshal(auditRec.Body.Bytes(), &resp)
	if len(resp.Invocations) != 1 {
		t.Fatalf("audit len = %d; want 1", len(resp.Invocations))
	}
	endpoint, _ := resp.Invocations[0]["endpoint"].(string)
	if endpoint == "" {
		t.Fatal("endpoint missing on completed invocation audit row")
	}
	// Endpoint MUST include the capability fragment so the O+ console can
	// disambiguate per-capability routes per the OpenAPI subset shape.
	if !strings.Contains(endpoint, "recommend_content") {
		t.Errorf("endpoint = %q; want capability fragment", endpoint)
	}
	// And it MUST NEVER be the legacy "unknown" placeholder.
	if endpoint == "unknown" {
		t.Errorf("endpoint = %q; placeholder is forbidden per honest-null contract", endpoint)
	}
}

// createContractWithName — capability + tier + rate limit
func createContractWithName(t *testing.T, r interface {
	ServeHTTP(http.ResponseWriter, *http.Request)
}, pid, capName, tier string, rate int) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"auth_method": "api_key",
		"capabilities": []map[string]any{
			{"name": capName, "tier": tier, "rate_limit_per_minute": rate},
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/contracts/"+pid, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("createContractWithName status = %d; body = %s", rec.Code, rec.Body.String())
	}
}

func padCorr(n int) string {
	// Build a unique correlation_id per invocation.
	const prefix = "01970000-0000-7000-c000-00000000"
	return prefix + padDigits(n, 4)
}

func padDigits(n, width int) string {
	s := []byte("0000")
	for i := 0; i < width && n > 0; i++ {
		s[width-1-i] = byte('0' + n%10)
		n /= 10
	}
	return string(s)
}
