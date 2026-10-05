// helpers_internal_test.go — direct unit tests for the small, pure helper
// funcs in the http adapter (package-internal so unexported identifiers are
// reachable). These have no HTTP-wiring side effects beyond writeJSON, so they
// are cheap to cover exhaustively.
package httpadapter

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/contract"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/invocation"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/partner"
)

func mustHelperReg(t *testing.T, id, domain string) *partner.Registration {
	t.Helper()
	r, err := partner.NewRegistration(partner.RegistrationParams{
		ID:                 id,
		OrgName:            "Acme",
		ContactEmail:       "ops@acme.example",
		Capabilities:       []string{"recommend_content"},
		RequestedRateLimit: 100,
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	r.PartnerDomain = domain
	r.AGID = "agid:partner:cap:01"
	return r
}

func TestResolveDispatchEndpoint(t *testing.T) {
	reg := mustHelperReg(t, "reg-1", "partner.example")
	if got := resolveDispatchEndpoint(reg, "recommend_content"); got != "https://partner.example/a2a/v1/recommend_content" {
		t.Errorf("with domain = %q", got)
	}
	nodomain := mustHelperReg(t, "reg-2", "")
	if got := resolveDispatchEndpoint(nodomain, "recommend_content"); got != "https://a2a.chora.site/a2a/invoke#recommend_content" {
		t.Errorf("without domain = %q", got)
	}
	if got := resolveDispatchEndpoint(reg, "  "); got != "" {
		t.Errorf("empty capability = %q; want empty", got)
	}
	// Trimming: a capability with padding is normalised.
	if got := resolveDispatchEndpoint(reg, "  recommend_content  "); !strings.HasSuffix(got, "/recommend_content") {
		t.Errorf("trimmed capability = %q", got)
	}
}

func TestNewUUIDv7_And_NewRandomToken(t *testing.T) {
	if got := newUUIDv7(); got == "" {
		t.Error("newUUIDv7 returned empty")
	}
	if got := newRandomToken(); got == "" || len(got) != 64 {
		t.Errorf("newRandomToken = %q (len=%d); want 64-hex", got, len(got))
	}
}

func TestTenantOrPlatform(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if got := tenantOrPlatform(r); got != "platform" {
		t.Errorf("no header = %q; want platform", got)
	}
	r.Header.Set("X-Chora-Tenant-Id", "  tenant-9  ")
	if got := tenantOrPlatform(r); got != "tenant-9" {
		t.Errorf("with header = %q; want trimmed tenant-9", got)
	}
}

func TestMaxInt(t *testing.T) {
	if got := maxInt(3, 1); got != 3 {
		t.Errorf("maxInt(3,1)=%d", got)
	}
	if got := maxInt(1, 3); got != 3 {
		t.Errorf("maxInt(1,3)=%d", got)
	}
	if got := maxInt(5, 5); got != 5 {
		t.Errorf("maxInt(5,5)=%d", got)
	}
}

func TestVerifyKeyHashOnly(t *testing.T) {
	reg := mustHelperReg(t, "reg-1", "")
	reg.APIKeyHash = sha256Hex("secret-key")
	if !verifyKeyHashOnly(reg, "secret-key") {
		t.Error("matching key must verify")
	}
	if verifyKeyHashOnly(reg, "wrong-key") {
		t.Error("mismatched key must not verify")
	}
	empty := mustHelperReg(t, "reg-2", "")
	if verifyKeyHashOnly(empty, "secret-key") {
		t.Error("empty stored hash must never verify")
	}
}

func TestDecodeJWTSubject(t *testing.T) {
	// "sub":"agid:test:01" base64url payload.
	payload := base64URLOf(`{"sub":"agid:test:01"}`)
	if got, err := decodeJWTSubject("Bearer header." + payload + ".sig"); err != nil || got != "agid:test:01" {
		t.Errorf("valid jwt = (%q, %v)", got, err)
	}
	// No Bearer prefix.
	if _, err := decodeJWTSubject("plain"); err == nil {
		t.Error("expected error for missing Bearer prefix")
	}
	// Malformed (single segment).
	if _, err := decodeJWTSubject("Bearer onepart"); err == nil {
		t.Error("expected error for malformed JWT")
	}
	// Payload has no sub claim → returns empty, no error.
	payload2 := base64URLOf(`{"iss":"x"}`)
	if got, err := decodeJWTSubject("Bearer h." + payload2 + ".s"); err != nil || got != "" {
		t.Errorf("no-sub jwt = (%q, %v)", got, err)
	}
}

func TestWriteJSON_And_WriteError(t *testing.T) {
	rec := httptest.NewRecorder()
	writeJSON(rec, http.StatusTeapot, map[string]any{"a": 1})
	if rec.Code != http.StatusTeapot {
		t.Errorf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("content-type = %q", ct)
	}

	rec2 := httptest.NewRecorder()
	writeError(rec2, http.StatusBadRequest, "BAD", "nope")
	if rec2.Code != http.StatusBadRequest {
		t.Errorf("status = %d", rec2.Code)
	}
	if !strings.Contains(rec2.Body.String(), `"code":"BAD"`) {
		t.Errorf("body = %s", rec2.Body.String())
	}
}

func TestWriteExtJSON_And_WriteExtError(t *testing.T) {
	rec := httptest.NewRecorder()
	writeExtJSON(rec, http.StatusAccepted, map[string]any{"ok": true})
	if rec.Code != http.StatusAccepted {
		t.Errorf("status = %d", rec.Code)
	}

	rec2 := httptest.NewRecorder()
	writeExtError(rec2, http.StatusUnprocessableEntity, "DNS_FAIL", "no record")
	if rec2.Code != http.StatusUnprocessableEntity {
		t.Errorf("status = %d", rec2.Code)
	}
	if !strings.Contains(rec2.Body.String(), `"code":"DNS_FAIL"`) {
		t.Errorf("body = %s", rec2.Body.String())
	}
}

func TestInvocationToMap_Branches(t *testing.T) {
	i, _ := invocation.New(invocation.NewParams{
		ID:            "inv-1",
		AGID:          "agid:p:c:01",
		PartnerID:     "p-1",
		Capability:    "recommend_content",
		CorrelationID: "corr-1",
		Endpoint:      "https://a2a.chora.site/a2a/invoke#recommend_content",
		Traceparent:   "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-aaaaaaaaaaaaaaaa-01",
	})
	end := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	if err := i.Complete(123); err != nil {
		t.Fatalf("complete: %v", err)
	}
	i.EndedAt = &end
	m := invocationToMap(i)
	if m["id"] != "inv-1" || m["status"] != "completed" {
		t.Errorf("map = %v", m)
	}
	if m["ended_at"] != end.Format(time.RFC3339) {
		t.Errorf("ended_at = %v", m["ended_at"])
	}
	if m["traceparent"] == "" || m["endpoint"] == "" {
		t.Errorf("traceparent/endpoint missing: %v", m)
	}

	// Empty traceparent/endpoint/ended_at → key omitted.
	i2, _ := invocation.New(invocation.NewParams{
		ID: "inv-2", AGID: "agid:2", PartnerID: "p-1",
		Capability: "x", CorrelationID: "c-2",
	})
	m2 := invocationToMap(i2)
	if _, ok := m2["ended_at"]; ok {
		t.Error("ended_at should be omitted when nil")
	}
	if _, ok := m2["endpoint"]; ok {
		t.Error("endpoint should be omitted when empty")
	}
}

func TestToContractResponse_Branches(t *testing.T) {
	c, err := contract.New(contract.NewParams{
		ID:         "c-1",
		PartnerID:  "p-1",
		AuthMethod: contract.AuthAPIKey,
		Capabilities: []contract.Capability{
			{Name: "recommend_content", Tier: contract.TierLow, RateLimitPerMin: 10},
		},
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	resp := toContractResponse(c)
	if len(resp.Capabilities) != 1 || resp.Capabilities[0]["name"] != "recommend_content" {
		t.Errorf("resp = %+v", resp)
	}
	if resp.SunsetAt != "" {
		t.Errorf("sunset should be empty; got %q", resp.SunsetAt)
	}

	sunset := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	c.SunsetAt = &sunset
	resp2 := toContractResponse(c)
	if resp2.SunsetAt != sunset.Format(time.RFC3339) {
		t.Errorf("sunset = %q", resp2.SunsetAt)
	}
}

func TestToRegistrationResponse_And_RegistrationToMap(t *testing.T) {
	reg := mustHelperReg(t, "reg-1", "partner.example")
	reg.DNSVerifyToken = "tok"
	resp := toRegistrationResponse(reg, "_chora-a2a.partner.example TXT chora-a2a-verify=tok")
	if resp.ID != "reg-1" || resp.DNSVerifyRecord == "" {
		t.Errorf("resp = %+v", resp)
	}
	m := registrationToMap(reg)
	if m["id"] != "reg-1" || m["partner_domain"] != "partner.example" {
		t.Errorf("map = %v", m)
	}
}

// -----------------------------------------------------------------------------
// tiny helpers
// -----------------------------------------------------------------------------

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func base64URLOf(raw string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// mustNewInvocationSmoke exercises the mustNewInvocation constructor (ID + the
// resolveDispatchEndpoint wiring) directly.
func TestMustNewInvocation_ProducesInvocation(t *testing.T) {
	reg := mustHelperReg(t, "reg-1", "partner.example")
	inv := mustNewInvocation(reg, "recommend_content", "corr-1", "")
	if inv == nil || inv.ID == "" || inv.Endpoint == "" {
		t.Error("mustNewInvocation produced an invalid invocation")
	}
	if inv.Endpoint != "https://partner.example/a2a/v1/recommend_content" {
		t.Errorf("endpoint = %q", inv.Endpoint)
	}
}
