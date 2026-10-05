// Package httpadapter_test exercises the HTTP adapter — the 5 endpoints
// defined in the user task spec for the chora-a2a-gateway skeleton:
//
//	GET  /healthz
//	GET  /readyz
//	POST /a2a/v1/invoke                          (X-AGID required, JWT decoded)
//	GET  /a2a/v1/partners/{agid}
//	POST /a2a/v1/partners                        (admin — placeholder)
//	GET  /a2a/v1/sessions/{correlation_id}
//
// CRITICAL: Every /a2a/v1/* call MUST require X-AGID. Suspended partners
// MUST be rejected with 403. Rate limit exceeded → 429. Append-only sessions
// — every invocation creates a new session.
//
// TDD RED phase — implementation does NOT yet exist.
package httpadapter_test

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	httpadapter "github.com/apollo-chora/chora-a2a-gateway/internal/adapter/http"
	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/inmem"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/partner"
)

const (
	agidA = "01970000-0000-7000-b000-000000000001"
	agidB = "01970000-0000-7000-b000-000000000002"
	corrA = "01970000-0000-7000-c000-000000000001"
	jwt   = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.signature_placeholder"
)

func newTestServer(t *testing.T) (*httpadapter.Router, *inmem.PartnerStore, *inmem.SessionStore, *inmem.IdentityStore, *inmem.RateLimiter) {
	t.Helper()
	ps := inmem.NewPartnerStore()
	ss := inmem.NewSessionStore()
	is := inmem.NewIdentityStore()
	rl := inmem.NewRateLimiter()

	// Seed a partner so /invoke + /partners/{agid} succeed.
	p, _ := partner.New(partner.NewParams{
		AGID:            agidA,
		Name:            "Acme",
		AllowedScopes:   []string{"sample.echo", "recommend_content"},
		RateLimitPerMin: 100,
		QuotaPerDay:     10000,
	})
	_ = ps.Put(p)
	rl.Configure(agidA, 100, 60_000_000_000) // 100/min

	r := httpadapter.NewRouter(ps, ss, is, rl)
	return r, ps, ss, is, rl
}

// -----------------------------------------------------------------------------
// Health
// -----------------------------------------------------------------------------

func TestGET_Healthz(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newTestServer(t)
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/healthz", nil)
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Errorf("status = %d; want 200", w.Code)
	}
	var got map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["status"] != "ok" {
		t.Errorf("status = %q; want ok", got["status"])
	}
}

func TestGET_Readyz(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newTestServer(t)
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/readyz", nil)
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Errorf("status = %d; want 200", w.Code)
	}
}

// -----------------------------------------------------------------------------
// /a2a/v1/invoke
// -----------------------------------------------------------------------------

func TestPOST_Invoke_Success(t *testing.T) {
	t.Parallel()
	r, _, ss, _, _ := newTestServer(t)

	body := []byte(`{"action":"sample.echo","params":{"hello":"world"}}`)
	req := httptest.NewRequest("POST", "/a2a/v1/invoke", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-AGID", agidA)
	req.Header.Set("X-Correlation-Id", corrA)
	req.Header.Set("Authorization", "Bearer "+jwt)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d; want 200; body=%s", w.Code, w.Body.String())
	}
	// Expect a session has been recorded for this correlation_id.
	got, err := ss.GetByCorrelationID(corrA)
	if err != nil {
		t.Fatalf("session not recorded: %v", err)
	}
	if got.AGID != agidA {
		t.Errorf("session AGID = %q; want %q", got.AGID, agidA)
	}

	// CRITICAL: response body must NOT contain a gcid field.
	if strings.Contains(strings.ToLower(w.Body.String()), "\"gcid\"") {
		t.Errorf("response body contains gcid — AGID-vs-GCID invariant violated. body=%s", w.Body.String())
	}
}

// X-AGID header is mandatory.
func TestPOST_Invoke_RejectsMissingAGID(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newTestServer(t)
	body := []byte(`{"action":"sample.echo","params":{}}`)
	req := httptest.NewRequest("POST", "/a2a/v1/invoke", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-Correlation-Id", corrA)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Errorf("status = %d; want 400 (missing X-AGID)", w.Code)
	}
}

// Unknown partner → 404.
func TestPOST_Invoke_RejectsUnknownPartner(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newTestServer(t)
	body := []byte(`{"action":"sample.echo","params":{}}`)
	req := httptest.NewRequest("POST", "/a2a/v1/invoke", bytes.NewReader(body))
	req.Header.Set("X-AGID", "01970000-0000-7000-b000-00000000ffff")
	req.Header.Set("X-Correlation-Id", corrA)
	req.Header.Set("Authorization", "Bearer "+jwt)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 404 {
		t.Errorf("status = %d; want 404", w.Code)
	}
}

// Suspended partner → 403.
func TestPOST_Invoke_RejectsSuspendedPartner(t *testing.T) {
	t.Parallel()
	r, ps, _, _, _ := newTestServer(t)
	p, _ := ps.Get(agidA)
	_ = p.Suspend("test")
	_ = ps.Put(p)

	body := []byte(`{"action":"sample.echo","params":{}}`)
	req := httptest.NewRequest("POST", "/a2a/v1/invoke", bytes.NewReader(body))
	req.Header.Set("X-AGID", agidA)
	req.Header.Set("X-Correlation-Id", corrA)
	req.Header.Set("Authorization", "Bearer "+jwt)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Errorf("status = %d; want 403 (suspended partner)", w.Code)
	}
}

// 100/min limit → 101st call returns 429.
func TestPOST_Invoke_RateLimit429(t *testing.T) {
	t.Parallel()
	r, _, _, _, rl := newTestServer(t)

	// Tighten the limit so the test is fast and deterministic.
	rl.Configure(agidA, 2, 60_000_000_000)

	body := []byte(`{"action":"sample.echo","params":{}}`)
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("POST", "/a2a/v1/invoke", bytes.NewReader(body))
		req.Header.Set("X-AGID", agidA)
		req.Header.Set("X-Correlation-Id", "01970000-0000-7000-c000-00000000000"+itoa(i))
		req.Header.Set("Authorization", "Bearer "+jwt)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatalf("warmup call %d: status = %d", i, w.Code)
		}
	}
	// The 3rd should be 429.
	req := httptest.NewRequest("POST", "/a2a/v1/invoke", bytes.NewReader(body))
	req.Header.Set("X-AGID", agidA)
	req.Header.Set("X-Correlation-Id", "01970000-0000-7000-c000-000000000099")
	req.Header.Set("Authorization", "Bearer "+jwt)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 429 {
		t.Errorf("status = %d; want 429", w.Code)
	}
}

// Strong invariant: every successful invoke creates a NEW session
// (append-only — no UPDATE; new entry per call).
func TestPOST_Invoke_AppendsNewSessionPerCall(t *testing.T) {
	t.Parallel()
	r, _, ss, _, _ := newTestServer(t)
	body := []byte(`{"action":"sample.echo","params":{}}`)

	corr1 := "01970000-0000-7000-c000-000000000a01"
	corr2 := "01970000-0000-7000-c000-000000000a02"

	for _, corr := range []string{corr1, corr2} {
		req := httptest.NewRequest("POST", "/a2a/v1/invoke", bytes.NewReader(body))
		req.Header.Set("X-AGID", agidA)
		req.Header.Set("X-Correlation-Id", corr)
		req.Header.Set("Authorization", "Bearer "+jwt)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatalf("invoke %s: status = %d", corr, w.Code)
		}
	}
	if _, err := ss.GetByCorrelationID(corr1); err != nil {
		t.Errorf("first session missing: %v", err)
	}
	if _, err := ss.GetByCorrelationID(corr2); err != nil {
		t.Errorf("second session missing: %v", err)
	}
}

// -----------------------------------------------------------------------------
// /a2a/v1/partners/{agid}
// -----------------------------------------------------------------------------

func TestGET_Partner_Success(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newTestServer(t)
	req := httptest.NewRequest("GET", "/a2a/v1/partners/"+agidA, nil)
	req.Header.Set("X-AGID", agidA)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Errorf("status = %d; want 200; body=%s", w.Code, w.Body.String())
	}
}

func TestGET_Partner_RequiresXAGID(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newTestServer(t)
	req := httptest.NewRequest("GET", "/a2a/v1/partners/"+agidA, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Errorf("status = %d; want 400 (missing X-AGID)", w.Code)
	}
}

func TestGET_Partner_NotFound(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newTestServer(t)
	req := httptest.NewRequest("GET", "/a2a/v1/partners/01970000-0000-7000-b000-000000000999", nil)
	req.Header.Set("X-AGID", agidA)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 404 {
		t.Errorf("status = %d; want 404", w.Code)
	}
}

// -----------------------------------------------------------------------------
// POST /a2a/v1/partners
// -----------------------------------------------------------------------------

func TestPOST_Partner_RegistersNew(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newTestServer(t)
	body := []byte(`{
		"agid":"01970000-0000-7000-b000-000000000333",
		"name":"NewPartner",
		"allowed_scopes":["x"],
		"rate_limit_per_minute":50,
		"quota_per_day":1000
	}`)
	req := httptest.NewRequest("POST", "/a2a/v1/partners", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-AGID", agidA)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 201 {
		t.Errorf("status = %d; want 201; body=%s", w.Code, w.Body.String())
	}
}

func TestPOST_Partner_RejectsBadJSON(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newTestServer(t)
	req := httptest.NewRequest("POST", "/a2a/v1/partners", bytes.NewReader([]byte("not json")))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-AGID", agidA)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Errorf("status = %d; want 400", w.Code)
	}
}

// -----------------------------------------------------------------------------
// /a2a/v1/sessions/{correlation_id}
// -----------------------------------------------------------------------------

func TestGET_Session_Success(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newTestServer(t)
	// Create a session via /invoke first.
	body := []byte(`{"action":"sample.echo","params":{}}`)
	req := httptest.NewRequest("POST", "/a2a/v1/invoke", bytes.NewReader(body))
	req.Header.Set("X-AGID", agidA)
	req.Header.Set("X-Correlation-Id", corrA)
	req.Header.Set("Authorization", "Bearer "+jwt)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("seed invoke: status %d", w.Code)
	}

	req2 := httptest.NewRequest("GET", "/a2a/v1/sessions/"+corrA, nil)
	req2.Header.Set("X-AGID", agidA)
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	if w2.Code != 200 {
		t.Errorf("status = %d; want 200; body=%s", w2.Code, w2.Body.String())
	}
	if strings.Contains(strings.ToLower(w2.Body.String()), "\"gcid\"") {
		t.Errorf("session response contains gcid; invariant violated: %s", w2.Body.String())
	}
}

func TestGET_Session_NotFound(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newTestServer(t)
	req := httptest.NewRequest("GET", "/a2a/v1/sessions/01970000-0000-7000-c000-000000000fff", nil)
	req.Header.Set("X-AGID", agidA)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 404 {
		t.Errorf("status = %d; want 404", w.Code)
	}
}

// -----------------------------------------------------------------------------
// JWT decode (no signature verify in skeleton — M14 will sign)
// -----------------------------------------------------------------------------

func TestPOST_Invoke_DecodesJWTWithoutVerifyingSignature(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newTestServer(t)

	// A "JWT" with a clearly bogus signature — should still pass the
	// skeleton handler because real signature verification is M14.
	bogus := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.bogus_signature_xxxxxxxxxxxxxxxxxx"
	body := []byte(`{"action":"sample.echo","params":{}}`)
	req := httptest.NewRequest("POST", "/a2a/v1/invoke", bytes.NewReader(body))
	req.Header.Set("X-AGID", agidA)
	req.Header.Set("X-Correlation-Id", "01970000-0000-7000-c000-000000000bbb")
	req.Header.Set("Authorization", "Bearer "+bogus)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Errorf("status = %d; want 200; bogus signature must be tolerated in skeleton; body=%s", w.Code, w.Body.String())
	}
}

// itoa avoids strconv import in test fixtures.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := []byte{}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
