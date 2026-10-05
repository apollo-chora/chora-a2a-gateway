// handler_extra_test.go — covers the legacy /a2a/v1/* router error branches
// that the primary handler_test.go does not: HTTP-method guards (405) across
// every registered route, and the remaining request-validation paths
// (missing correlation id, malformed body, missing action, duplicate
// correlation id, empty path params).
package httpadapter_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// -----------------------------------------------------------------------------
// method guards (405) across all legacy routes
// -----------------------------------------------------------------------------

func TestLegacyRouter_MethodMethodNotAllowed_Branch(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newTestServer(t)

	cases := []struct {
		name string
		meth string
		path string
	}{
		{"healthz-post", http.MethodPost, "/healthz"},
		{"healthz-put", http.MethodPut, "/healthz/"},
		{"readyz-delete", http.MethodDelete, "/readyz"},
		{"invoke-get", http.MethodGet, "/a2a/v1/invoke"},
		{"partnersCollection-get", http.MethodGet, "/a2a/v1/partners"},
		{"partnersByAGID-post", http.MethodPost, "/a2a/v1/partners/" + agidA},
		{"sessionsByCorrelation-post", http.MethodPost, "/a2a/v1/sessions/" + corrA},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(tc.meth, tc.path, nil)
			req.Header.Set("X-AGID", agidA)
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)
			if rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("status = %d; want 405", rec.Code)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// /a2a/v1/invoke — remaining validation branches
// -----------------------------------------------------------------------------

func TestPOST_Invoke_MissingCorrelationID(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/a2a/v1/invoke", nil)
	req.Header.Set("X-AGID", agidA) // no X-Correlation-Id
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "MISSING_CORRELATION_ID") {
		t.Errorf("status = %d body = %s", rec.Code, rec.Body.String())
	}
}

func TestPOST_Invoke_BadBody(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/a2a/v1/invoke", bytes.NewReader([]byte("{not json")))
	req.Header.Set("X-AGID", agidA)
	req.Header.Set("X-Correlation-Id", corrA)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "BAD_BODY") {
		t.Errorf("status = %d body = %s", rec.Code, rec.Body.String())
	}
}

func TestPOST_Invoke_MissingAction(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/a2a/v1/invoke", bytes.NewReader([]byte(`{"params":{}}`)))
	req.Header.Set("X-AGID", agidA)
	req.Header.Set("X-Correlation-Id", corrA)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "MISSING_ACTION") {
		t.Errorf("status = %d body = %s", rec.Code, rec.Body.String())
	}
}

func TestPOST_Invoke_DuplicateCorrelationID(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newTestServer(t)
	body := []byte(`{"action":"sample.echo","params":{}}`)

	do := func() int {
		req := httptest.NewRequest(http.MethodPost, "/a2a/v1/invoke", bytes.NewReader(body))
		req.Header.Set("X-AGID", agidA)
		req.Header.Set("X-Correlation-Id", corrA)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := do(); code != http.StatusOK {
		t.Fatalf("first invoke = %d; want 200", code)
	}
	if code := do(); code != http.StatusConflict {
		t.Errorf("second invoke with same correlation id = %d; want 409", code)
	}
}

// -----------------------------------------------------------------------------
// /a2a/v1/partners/{agid} + /a2a/v1/sessions/{cid} — empty path param imports
// -----------------------------------------------------------------------------

func TestGET_Partner_EmptyPathParam(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/a2a/v1/partners/", nil)
	req.Header.Set("X-AGID", agidA)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "MISSING_PARTNER_AGID") {
		t.Errorf("status = %d body = %s", rec.Code, rec.Body.String())
	}
}

func TestGET_Session_EmptyPathParam(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/a2a/v1/sessions/", nil)
	req.Header.Set("X-AGID", agidA)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "MISSING_CORRELATION_ID") {
		t.Errorf("status = %d body = %s", rec.Code, rec.Body.String())
	}
}

func TestGET_Session_MissingAGID(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/a2a/v1/sessions/"+corrA, nil) // no X-AGID
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "MISSING_AGID") {
		t.Errorf("status = %d body = %s", rec.Code, rec.Body.String())
	}
}
