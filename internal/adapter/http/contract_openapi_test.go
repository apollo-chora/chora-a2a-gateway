// Package httpadapter_test — contract_openapi_test.go: tests for
// /contracts/{partner_id}/openapi.yaml per-consumer OpenAPI export.
package httpadapter_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestContractsOpenAPI_HappyPath(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newExtServer(t)
	pid := registerOne(t, r, "Acme")
	approveOne(t, r, pid)
	createContract(t, r, pid, "high", 600)

	req := httptest.NewRequest(http.MethodGet, "/contracts/"+pid+"/openapi.yaml", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "openapi:") || !strings.Contains(body, "paths:") {
		t.Errorf("body missing openapi structure: %s", body)
	}
	if !strings.Contains(body, "x-chora-tier: high") {
		t.Errorf("body missing tier extension: %s", body)
	}
	if !strings.Contains(body, "x-chora-rate-limit-per-minute: 600") {
		t.Errorf("body missing rate-limit extension")
	}
	// Server URL is a2a.chora.site.
	if !strings.Contains(body, "https://a2a.chora.site") {
		t.Errorf("body missing a2a.chora.site URL")
	}
	if rec.Header().Get("Content-Type") != "application/yaml; charset=utf-8" {
		t.Errorf("Content-Type = %q", rec.Header().Get("Content-Type"))
	}
}

func TestContractsOpenAPI_NoContracts(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newExtServer(t)
	pid := registerOne(t, r, "Empty")
	approveOne(t, r, pid)
	// no contracts created.

	req := httptest.NewRequest(http.MethodGet, "/contracts/"+pid+"/openapi.yaml", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d; want 404", rec.Code)
	}
}

func TestContractsOpenAPI_RejectsMethods(t *testing.T) {
	t.Parallel()
	r, _, _, _, _ := newExtServer(t)
	pid := registerOne(t, r, "Acme")
	approveOne(t, r, pid)
	createContract(t, r, pid, "high", 600)

	req := httptest.NewRequest(http.MethodPost, "/contracts/"+pid+"/openapi.yaml", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d; want 405", rec.Code)
	}
}
