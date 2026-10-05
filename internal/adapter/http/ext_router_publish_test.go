// Package httpadapter_test — publisher fail-loud contract.
//
// Every ExtRouter handler that calls r.publisher.Publish() must NOT
// silently discard a Publish error. Publish() can genuinely fail in
// production — TransactionalOutboxPublisher.Publish (see
// internal/adapter/outbox/publisher.go) writes to the a2a_outbox_events
// table, and that DB insert can fail for real reasons: connection loss,
// constraint violation, unregistered/malformed topic. A discarded
// `_ = r.publisher.Publish(...)` means a governance/audit event (many are
// IMDA-dimension-tagged) vanishes with zero trace — a fail-loud violation
// per CLAUDE.md.
//
// These tests wire a Publisher stub that always fails and assert, at a
// representative sample of call-site shapes:
//  1. the HTTP response is UNCHANGED — Publish is intentionally
//     best-effort at every call site in ext_router.go: the domain state
//     write has already committed, or the response already carries a
//     specific business-decision error code, before Publish is
//     attempted. Converting a Publish failure into a 500 would either
//     mislabel an already-successful mutation as failed (inviting
//     client retries that mint duplicate IDs — these routes accept no
//     caller-supplied idempotency key) or clobber a correct
//     403/422/429 with a meaningless 500.
//  2. the failure is SURFACED via a loud log line — never silently
//     swallowed.
package httpadapter_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/dns"
	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/events"
	httpadapter "github.com/apollo-chora/chora-a2a-gateway/internal/adapter/http"
	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/repo/inmem"
)

// failingPublisher always fails Publish — it exists solely to prove
// callers surface (never swallow) the error.
type failingPublisher struct{}

func (failingPublisher) Publish(events.Event) error {
	return errors.New("boom: outbox insert failed")
}

// newExtServerFailingPublish builds an ExtRouter wired the same way as
// newExtServer (see partner_handler_test.go) but with a Publisher that
// always errors.
func newExtServerFailingPublish(t *testing.T) *httpadapter.ExtRouter {
	t.Helper()
	return httpadapter.NewExtRouter(httpadapter.ExtConfig{
		Registrations: inmem.NewRegistrationRepo(),
		Contracts:     inmem.NewContractRepo(),
		Invocations:   inmem.NewInvocationRepo(),
		Publisher:     failingPublisher{},
	})
}

// captureLog redirects the shared `log` package output for the rest of
// the test and returns a getter for what has been written so far.
func captureLog(t *testing.T) func() string {
	t.Helper()
	var buf bytes.Buffer
	origOut, origFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(origOut)
		log.SetFlags(origFlags)
	})
	return func() string { return buf.String() }
}

func TestExtRouter_PublishFailure_RegisterStillSucceeds_AndIsLogged(t *testing.T) {
	r := newExtServerFailingPublish(t)
	getLog := captureLog(t)

	body, _ := json.Marshal(map[string]any{
		"org_name":             "Acme Tutor Co",
		"contact_email":        "ops@acme.example",
		"capabilities":         []string{"recommend_content"},
		"requested_rate_limit": 100,
	})
	req := httptest.NewRequest(http.MethodPost, "/partners/register", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d; body = %s — a Publish failure must not fail a write that already committed", rec.Code, rec.Body.String())
	}
	if logged := getLog(); !strings.Contains(logged, "chora.a2a.partner.registered.v1") {
		t.Errorf("publish failure not surfaced in logs; got %q", logged)
	}
}

func TestExtRouter_PublishFailure_AdminSuspend_StillSucceeds_AndIsLogged(t *testing.T) {
	r := newExtServerFailingPublish(t)
	pid := registerOne(t, r, "Acme")
	approveOne(t, r, pid)

	getLog := captureLog(t)
	suspBody, _ := json.Marshal(map[string]any{
		"approver_gcid": "01970000-0000-7000-9000-000000000001",
		"reason":        "compliance_review",
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/partners/"+pid+":suspend", bytes.NewReader(suspBody))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body = %s", rec.Code, rec.Body.String())
	}
	if logged := getLog(); !strings.Contains(logged, "chora.a2a.partner.suspended.v1") {
		t.Errorf("suspend publish failure not logged; got %q", logged)
	}
}

// mcpConfigOp's topic is chosen dynamically ("suspended.v1" |
// "reinstated.v1") rather than being a literal at the call site — this
// exercises that branch specifically.
func TestExtRouter_PublishFailure_MCPAddonSuspend_StillSucceeds_AndIsLogged(t *testing.T) {
	r := newExtServerFailingPublish(t)

	mkBody, _ := json.Marshal(map[string]any{"allowed_tools": []string{"atom_search"}})
	mkRec := httptest.NewRecorder()
	r.ServeHTTP(mkRec, httptest.NewRequest(http.MethodPost, "/admin/mcp/tenant-x", bytes.NewReader(mkBody)))
	if mkRec.Code != http.StatusCreated {
		t.Fatalf("mcp config create status = %d; body = %s", mkRec.Code, mkRec.Body.String())
	}

	getLog := captureLog(t)
	suspRec := httptest.NewRecorder()
	r.ServeHTTP(suspRec, httptest.NewRequest(http.MethodPost, "/admin/mcp/tenant-x:suspend", nil))

	if suspRec.Code != http.StatusOK {
		t.Fatalf("mcp suspend status = %d; body = %s", suspRec.Code, suspRec.Body.String())
	}
	if logged := getLog(); !strings.Contains(logged, "chora.a2a.mcp_addon.suspended.v1") {
		t.Errorf("mcp suspend publish failure not logged; got %q", logged)
	}
}

// The /a2a/invoke scope-denied branch has already decided its response
// (403 SCOPE_DENIED) before attempting the audit-trail Publish — a
// Publish failure must not clobber that decision with a 500.
func TestExtRouter_PublishFailure_InvokeScopeDenied_Preserves403_AndLogs(t *testing.T) {
	r := newExtServerFailingPublish(t)
	pid := registerOne(t, r, "Acme")
	_, key := approveOne(t, r, pid)
	createContractWithName(t, r, pid, "recommend_content", "low", 60)

	getLog := captureLog(t)
	body, _ := json.Marshal(map[string]any{"capability": "write_persona_memory"})
	req := httptest.NewRequest(http.MethodPost, "/a2a/invoke", bytes.NewReader(body))
	req.Header.Set("X-Partner-Id", pid)
	req.Header.Set("X-API-Key", key)
	req.Header.Set("X-Correlation-Id", "01970000-0000-7000-c000-000000000099")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d; want 403 — a Publish failure on the audit event must not change the business decision", rec.Code)
	}
	if logged := getLog(); !strings.Contains(logged, "chora.a2a.invocation.scope_denied.v1") {
		t.Errorf("scope-denied publish failure not logged; got %q", logged)
	}
}

// dnsVerify's failed-verification branch is the one call site with NO
// prior state mutation at all (reg is never Put when verification
// fails) — it publishes purely to record the failed attempt.
func TestExtRouter_PublishFailure_DNSVerifyFailed_Preserves422_AndLogs(t *testing.T) {
	regs := inmem.NewRegistrationRepo()
	mock := dns.NewMockResolver()
	mock.SeedTXT("_chora-a2a.acme.example", []string{"chora-a2a-verify=BAD"})
	r := httpadapter.NewExtRouter(httpadapter.ExtConfig{
		Registrations: regs,
		Contracts:     inmem.NewContractRepo(),
		Invocations:   inmem.NewInvocationRepo(),
		Publisher:     failingPublisher{},
		DNSResolver:   mock,
	})

	body, _ := json.Marshal(map[string]any{
		"org_name":             "Acme",
		"contact_email":        "ops@acme.example",
		"capabilities":         []string{"recommend"},
		"requested_rate_limit": 60,
		"partner_domain":       "acme.example",
	})
	regRec := httptest.NewRecorder()
	r.ServeHTTP(regRec, httptest.NewRequest(http.MethodPost, "/partners/register", bytes.NewReader(body)))
	var regResp map[string]any
	_ = json.Unmarshal(regRec.Body.Bytes(), &regResp)
	id, _ := regResp["id"].(string)
	if id == "" {
		t.Fatal("id missing")
	}
	reg, _ := regs.Get(id)
	reg.DNSVerifyToken = "GOOD" // mismatches the seeded BAD TXT record
	_ = regs.Put(reg)

	getLog := captureLog(t)
	vBody, _ := json.Marshal(map[string]any{"registration_id": id})
	vRec := httptest.NewRecorder()
	r.ServeHTTP(vRec, httptest.NewRequest(http.MethodPost, "/admin/dns/verify", bytes.NewReader(vBody)))

	if vRec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d; want 422", vRec.Code)
	}
	if logged := getLog(); !strings.Contains(logged, "chora.a2a.dns_txt.failed.v1") {
		t.Errorf("dns-verify-failed publish failure not logged; got %q", logged)
	}
}
