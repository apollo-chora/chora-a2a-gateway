// Package httpadapter_test — O+ listing handlers (Phase B7 of the O+
// hydration plan; .claude/plans/atomic-napping-spring.md).
//
// Routes under test:
//
//	GET /api/v1/a2a/contracts                  list all non-deleted contracts
//	GET /api/v1/a2a/identities                 list partner registrations (AGIDs)
//	GET /api/v1/a2a/invocations?since=RFC3339  list invocations
//
// Per ADR-132 §6 (A2A Console parity) + CLAUDE.md §1: response shape never
// contains a `gcid` field — partner-facing audit is AGID-only.
package httpadapter_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	httpadapter "github.com/apollo-chora/chora-a2a-gateway/internal/adapter/http"
	legacyinmem "github.com/apollo-chora/chora-a2a-gateway/internal/adapter/inmem"
	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/repo/inmem"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/agent_identity"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/contract"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/invocation"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/partner"
)

// oplusTestNow is a deterministic clock for trust-level test cases.
var oplusTestNow = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

func newOPlusServer(t *testing.T) (*httpadapter.OPlusRouter, *inmem.RegistrationRepo, *inmem.ContractRepo, *inmem.InvocationRepo) {
	t.Helper()
	regs := inmem.NewRegistrationRepo()
	cons := inmem.NewContractRepo()
	invs := inmem.NewInvocationRepo()
	r := httpadapter.NewOPlusRouter(httpadapter.OPlusConfig{
		Registrations: regs,
		Contracts:     cons,
		Invocations:   invs,
	})
	return r, regs, cons, invs
}

// newOPlusServerWithIdentities mounts the OPlusRouter with the legacy
// IdentityStore wired so the /api/v1/a2a/identities listing can surface
// real public-key fingerprints. Also pins `Now` for deterministic
// trust-level derivation across the table cases below.
func newOPlusServerWithIdentities(t *testing.T) (
	*httpadapter.OPlusRouter,
	*inmem.RegistrationRepo,
	*inmem.InvocationRepo,
	*legacyinmem.IdentityStore,
) {
	t.Helper()
	regs := inmem.NewRegistrationRepo()
	cons := inmem.NewContractRepo()
	invs := inmem.NewInvocationRepo()
	ids := legacyinmem.NewIdentityStore()
	r := httpadapter.NewOPlusRouter(httpadapter.OPlusConfig{
		Registrations: regs,
		Contracts:     cons,
		Invocations:   invs,
		Identities:    ids,
		Now:           func() time.Time { return oplusTestNow },
	})
	return r, regs, invs, ids
}

// -----------------------------------------------------------------------------
// GET /api/v1/a2a/contracts
// -----------------------------------------------------------------------------

func TestOPlus_ListContracts_Empty(t *testing.T) {
	t.Parallel()
	r, _, _, _ := newOPlusServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/a2a/contracts", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body = %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	got, ok := resp["contracts"].([]any)
	if !ok {
		t.Fatalf("contracts field missing or wrong type: %#v", resp)
	}
	if len(got) != 0 {
		t.Errorf("len(contracts) = %d; want 0", len(got))
	}
}

func TestOPlus_ListContracts_ReturnsActive(t *testing.T) {
	t.Parallel()
	r, _, cons, _ := newOPlusServer(t)

	c, err := contract.New(contract.NewParams{
		ID:         "01970000-0000-7000-c000-000000000c01",
		PartnerID:  "01970000-0000-7000-c000-000000000p01",
		AuthMethod: contract.AuthAPIKey,
		Capabilities: []contract.Capability{
			{Name: "recommend_content", Tier: contract.TierMedium, RateLimitPerMin: 600},
		},
	})
	if err != nil {
		t.Fatalf("contract.New: %v", err)
	}
	if err := cons.Put(c); err != nil {
		t.Fatalf("Put: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/a2a/contracts", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body = %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	got, _ := resp["contracts"].([]any)
	if len(got) != 1 {
		t.Fatalf("len(contracts) = %d; want 1", len(got))
	}
	first, _ := got[0].(map[string]any)
	if _, hasGcid := first["gcid"]; hasGcid {
		t.Errorf("response leaks gcid field (CLAUDE.md §1 invariant)")
	}
	if first["partner_id"] != "01970000-0000-7000-c000-000000000p01" {
		t.Errorf("partner_id = %v; want 01970000-0000-7000-c000-000000000p01", first["partner_id"])
	}
}

func TestOPlus_ListContracts_RejectsNonGet(t *testing.T) {
	t.Parallel()
	r, _, _, _ := newOPlusServer(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/a2a/contracts", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d; want 405", rec.Code)
	}
}

// -----------------------------------------------------------------------------
// GET /api/v1/a2a/identities
// -----------------------------------------------------------------------------

func TestOPlus_ListIdentities_Empty(t *testing.T) {
	t.Parallel()
	r, _, _, _ := newOPlusServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/a2a/identities", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body = %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	got, ok := resp["identities"].([]any)
	if !ok {
		t.Fatalf("identities field missing or wrong type: %#v", resp)
	}
	if len(got) != 0 {
		t.Errorf("len(identities) = %d; want 0", len(got))
	}
}

func TestOPlus_ListIdentities_ReturnsRegistrations(t *testing.T) {
	t.Parallel()
	r, regs, _, _ := newOPlusServer(t)

	reg, err := partner.NewRegistration(partner.RegistrationParams{
		ID:                 "01970000-0000-7000-c000-000000000r01",
		OrgName:            "Acme Tutor",
		ContactEmail:       "ops@acme.example",
		Capabilities:       []string{"recommend_content"},
		RequestedRateLimit: 100,
	})
	if err != nil {
		t.Fatalf("NewRegistration: %v", err)
	}
	if err := regs.Put(reg); err != nil {
		t.Fatalf("Put: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/a2a/identities", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body = %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	got, _ := resp["identities"].([]any)
	if len(got) != 1 {
		t.Fatalf("len(identities) = %d; want 1", len(got))
	}
	first, _ := got[0].(map[string]any)
	if _, hasGcid := first["gcid"]; hasGcid {
		t.Errorf("response leaks gcid field (CLAUDE.md §1 invariant)")
	}
	if first["org_name"] != "Acme Tutor" {
		t.Errorf("org_name = %v; want Acme Tutor", first["org_name"])
	}
}

// -----------------------------------------------------------------------------
// GET /api/v1/a2a/invocations?since=...
// -----------------------------------------------------------------------------

func TestOPlus_ListInvocations_Empty(t *testing.T) {
	t.Parallel()
	r, _, _, _ := newOPlusServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/a2a/invocations", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body = %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	got, ok := resp["invocations"].([]any)
	if !ok {
		t.Fatalf("invocations field missing or wrong type: %#v", resp)
	}
	if len(got) != 0 {
		t.Errorf("len(invocations) = %d; want 0", len(got))
	}
}

func TestOPlus_ListInvocations_FilterBySince(t *testing.T) {
	t.Parallel()
	r, _, _, invs := newOPlusServer(t)

	// Seed two invocations — one old (pre-cutoff), one new.
	oldInv, err := invocation.New(invocation.NewParams{
		ID:            "01970000-0000-7000-c000-000000000i01",
		AGID:          "agid-acme-001",
		PartnerID:     "01970000-0000-7000-c000-000000000p01",
		Capability:    "recommend_content",
		CorrelationID: "corr-old",
	})
	if err != nil {
		t.Fatalf("invocation.New old: %v", err)
	}
	// Backdate to make it pre-cutoff deterministically.
	oldInv.StartedAt = time.Now().UTC().Add(-2 * time.Hour)
	if err := invs.Append(oldInv); err != nil {
		t.Fatalf("Append old: %v", err)
	}
	newInv, err := invocation.New(invocation.NewParams{
		ID:            "01970000-0000-7000-c000-000000000i02",
		AGID:          "agid-acme-001",
		PartnerID:     "01970000-0000-7000-c000-000000000p01",
		Capability:    "recommend_content",
		CorrelationID: "corr-new",
	})
	if err != nil {
		t.Fatalf("invocation.New new: %v", err)
	}
	if err := invs.Append(newInv); err != nil {
		t.Fatalf("Append new: %v", err)
	}

	// Cutoff between old and new.
	cutoff := time.Now().UTC().Add(-1 * time.Hour).Format(time.RFC3339)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/a2a/invocations?since="+cutoff, nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body = %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	got, _ := resp["invocations"].([]any)
	if len(got) != 1 {
		t.Fatalf("len(invocations) = %d; want 1 (post-cutoff only)", len(got))
	}
	first, _ := got[0].(map[string]any)
	if _, hasGcid := first["gcid"]; hasGcid {
		t.Errorf("response leaks gcid field (CLAUDE.md §1 invariant)")
	}
	if first["correlation_id"] != "corr-new" {
		t.Errorf("correlation_id = %v; want corr-new", first["correlation_id"])
	}
}

// Endpoint MUST be exposed on the O+ invocation list response when present —
// the BFF transformer passes it through to the FE A2A console (clearing the
// pre-2026-05-26 TODO(M12) placeholder).
func TestOPlus_ListInvocations_ExposesEndpoint(t *testing.T) {
	t.Parallel()
	r, _, _, invs := newOPlusServer(t)

	inv, err := invocation.New(invocation.NewParams{
		ID:            "01970000-0000-7000-c000-000000000i03",
		AGID:          "agid-acme-002",
		PartnerID:     "01970000-0000-7000-c000-000000000p02",
		Capability:    "recommend_content",
		CorrelationID: "corr-endpoint",
		Endpoint:      "https://a2a.chora.site/a2a/invoke#recommend_content",
	})
	if err != nil {
		t.Fatalf("invocation.New: %v", err)
	}
	if err := invs.Append(inv); err != nil {
		t.Fatalf("Append: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/a2a/invocations", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body = %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	got, _ := resp["invocations"].([]any)
	if len(got) != 1 {
		t.Fatalf("len(invocations) = %d; want 1", len(got))
	}
	first, _ := got[0].(map[string]any)
	if first["endpoint"] != "https://a2a.chora.site/a2a/invoke#recommend_content" {
		t.Errorf("endpoint = %v; want canonical capability URL preserved", first["endpoint"])
	}
}

// When an invocation row has no endpoint (legacy rows / scope-denied before
// dispatch resolution), the response MUST NOT contain an "endpoint" key with
// a placeholder string. Per [[feedback-no-stubs-real-wiring]] — omit (null
// contract) rather than substitute "unknown".
func TestOPlus_ListInvocations_OmitsEndpointWhenAbsent(t *testing.T) {
	t.Parallel()
	r, _, _, invs := newOPlusServer(t)

	inv, err := invocation.New(invocation.NewParams{
		ID:            "01970000-0000-7000-c000-000000000i04",
		AGID:          "agid-acme-003",
		PartnerID:     "01970000-0000-7000-c000-000000000p03",
		Capability:    "recommend_content",
		CorrelationID: "corr-no-endpoint",
		// Endpoint deliberately omitted.
	})
	if err != nil {
		t.Fatalf("invocation.New: %v", err)
	}
	if err := invs.Append(inv); err != nil {
		t.Fatalf("Append: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/a2a/invocations", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body = %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	got, _ := resp["invocations"].([]any)
	if len(got) != 1 {
		t.Fatalf("len(invocations) = %d; want 1", len(got))
	}
	first, _ := got[0].(map[string]any)
	if v, has := first["endpoint"]; has {
		t.Errorf("endpoint key present (= %v); want omitted on legacy rows (no 'unknown' placeholder)", v)
	}
}

func TestOPlus_ListInvocations_BadSince(t *testing.T) {
	t.Parallel()
	r, _, _, _ := newOPlusServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/a2a/invocations?since=not-a-time", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400", rec.Code)
	}
}

// -----------------------------------------------------------------------------
// trust_level + key_fingerprint enrichment on /api/v1/a2a/identities
// (audit finding #4 — debt-free wiring per [[feedback-no-stubs-real-wiring]]).
// -----------------------------------------------------------------------------

const (
	ed25519PubKeyPEMFixture = "-----BEGIN PUBLIC KEY-----\n" +
		"MCowBQYDK2VwAyEAxqLG2TODlPubAxbXdHbWMxbe66ix3OFv5h99q9JtNAg=\n" +
		"-----END PUBLIC KEY-----"
)

// seedMatureApprovedRegistration constructs an approved + DNS-verified
// Registration matured (60 days since approval) for the trust-level
// test cases below.
func seedMatureApprovedRegistration(t *testing.T, regs *inmem.RegistrationRepo, regID, agid string) *partner.Registration {
	t.Helper()
	r, err := partner.NewRegistration(partner.RegistrationParams{
		ID:                 regID,
		OrgName:            "Acme Tutor",
		ContactEmail:       "ops@acme.example",
		Capabilities:       []string{"recommend_content"},
		RequestedRateLimit: 100,
	})
	if err != nil {
		t.Fatalf("NewRegistration: %v", err)
	}
	if _, err := r.Approve(partner.ApprovalParams{
		ApprovedByGCID: "01970000-0000-7000-9000-0000000000aa",
		Tier:           partner.TierMedium,
	}); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	// Override the AGID so we can correlate with the identity store key.
	if agid != "" {
		r.AGID = agid
	}
	approvedAt := oplusTestNow.Add(-60 * 24 * time.Hour)
	r.ApprovedAt = &approvedAt
	r.DNSVerified = true
	verifiedAt := approvedAt
	r.DNSVerifiedAt = &verifiedAt
	if err := regs.Put(r); err != nil {
		t.Fatalf("Put registration: %v", err)
	}
	return r
}

func TestOPlus_ListIdentities_TrustLevel_VerifiedWhenMatureAndCleanRecord(t *testing.T) {
	t.Parallel()
	r, regs, _, _ := newOPlusServerWithIdentities(t)
	seedMatureApprovedRegistration(t, regs,
		"01970000-0000-7000-c000-000000000r10", "agid:test:r10:01")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/a2a/identities", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body = %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	got, _ := resp["identities"].([]any)
	if len(got) != 1 {
		t.Fatalf("len(identities) = %d", len(got))
	}
	row, _ := got[0].(map[string]any)
	if row["trust_level"] != "verified" {
		t.Errorf("trust_level = %v; want verified", row["trust_level"])
	}
}

func TestOPlus_ListIdentities_TrustLevel_PilotWhenFresh(t *testing.T) {
	t.Parallel()
	r, regs, _, _ := newOPlusServerWithIdentities(t)

	// 10-day-old approved + DNS-verified.
	reg := seedMatureApprovedRegistration(t, regs,
		"01970000-0000-7000-c000-000000000r11", "agid:test:r11:01")
	approvedAt := oplusTestNow.Add(-10 * 24 * time.Hour)
	reg.ApprovedAt = &approvedAt

	req := httptest.NewRequest(http.MethodGet, "/api/v1/a2a/identities", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	got, _ := resp["identities"].([]any)
	row, _ := got[0].(map[string]any)
	if row["trust_level"] != "pilot" {
		t.Errorf("trust_level = %v; want pilot (10 days old)", row["trust_level"])
	}
}

func TestOPlus_ListIdentities_TrustLevel_ExperimentalWhenDNSUnverified(t *testing.T) {
	t.Parallel()
	r, regs, _, _ := newOPlusServerWithIdentities(t)
	reg := seedMatureApprovedRegistration(t, regs,
		"01970000-0000-7000-c000-000000000r12", "agid:test:r12:01")
	reg.DNSVerified = false
	reg.DNSVerifiedAt = nil

	req := httptest.NewRequest(http.MethodGet, "/api/v1/a2a/identities", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	got, _ := resp["identities"].([]any)
	row, _ := got[0].(map[string]any)
	if row["trust_level"] != "experimental" {
		t.Errorf("trust_level = %v; want experimental (DNS not verified)", row["trust_level"])
	}
}

func TestOPlus_ListIdentities_TrustLevel_PilotWhenErrorRateExceedsThreshold(t *testing.T) {
	t.Parallel()
	r, regs, invs, _ := newOPlusServerWithIdentities(t)
	seedMatureApprovedRegistration(t, regs,
		"01970000-0000-7000-c000-000000000r13", "agid:test:r13:01")

	// Seed 100 invocations: 95 completed + 5 failed → 5% → pilot.
	regID := "01970000-0000-7000-c000-000000000r13"
	for i := 0; i < 95; i++ {
		inv, err := invocation.New(invocation.NewParams{
			ID:            "01970000-0000-7000-d000-" + indexHex(i),
			AGID:          "agid:test:r13:01",
			PartnerID:     regID,
			Capability:    "recommend_content",
			CorrelationID: "ok-" + indexHex(i),
		})
		if err != nil {
			t.Fatalf("invocation.New: %v", err)
		}
		inv.StartedAt = oplusTestNow.Add(-time.Duration(i+1) * time.Hour)
		_ = inv.Complete(128)
		if err := invs.Append(inv); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	for i := 95; i < 100; i++ {
		inv, err := invocation.New(invocation.NewParams{
			ID:            "01970000-0000-7000-d000-" + indexHex(i),
			AGID:          "agid:test:r13:01",
			PartnerID:     regID,
			Capability:    "recommend_content",
			CorrelationID: "err-" + indexHex(i),
		})
		if err != nil {
			t.Fatalf("invocation.New: %v", err)
		}
		inv.StartedAt = oplusTestNow.Add(-time.Duration(i+1) * time.Hour)
		_ = inv.Fail("UPSTREAM_500")
		if err := invs.Append(inv); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/a2a/identities", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	got, _ := resp["identities"].([]any)
	row, _ := got[0].(map[string]any)
	if row["trust_level"] != "pilot" {
		t.Errorf("trust_level = %v; want pilot (5%% error rate)", row["trust_level"])
	}
}

func TestOPlus_ListIdentities_KeyFingerprint_PresentWhenIdentityStored(t *testing.T) {
	t.Parallel()
	r, regs, _, ids := newOPlusServerWithIdentities(t)

	const agid = "agid:test:r14:01"
	seedMatureApprovedRegistration(t, regs,
		"01970000-0000-7000-c000-000000000r14", agid)

	// Real ExternalAgentIdentity stored — fingerprint MUST be the SHA-256
	// of the PEM, never sha256(agid).
	id, err := agent_identity.New(agent_identity.NewParams{
		AGID:         agid,
		PublicKeyPEM: ed25519PubKeyPEMFixture,
		Algorithm:    agent_identity.AlgEd25519,
	})
	if err != nil {
		t.Fatalf("agent_identity.New: %v", err)
	}
	if err := ids.Put(id); err != nil {
		t.Fatalf("ids.Put: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/a2a/identities", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	got, _ := resp["identities"].([]any)
	row, _ := got[0].(map[string]any)
	fp, _ := row["key_fingerprint"].(string)
	if fp == "" {
		t.Fatalf("key_fingerprint empty; want SHA-256 of PEM")
	}
	if fp != id.KeyFingerprint {
		t.Errorf("key_fingerprint = %q; want %q (real PEM sha256)", fp, id.KeyFingerprint)
	}
	// Defensively assert it is NOT sha256(agid) — the previous TODO(M12)
	// placeholder we just removed.
	if got, want := fp, "sha256:"+agid; got == want {
		t.Errorf("key_fingerprint = %q; placeholder regression — should be the PEM sha256", got)
	}
	rotated, _ := row["rotated_at"].(string)
	if rotated == "" {
		t.Errorf("rotated_at empty; want RFC3339 timestamp from identity.UpdatedAt")
	}
}

func TestOPlus_ListIdentities_KeyFingerprint_EmptyWhenIdentityAbsent(t *testing.T) {
	t.Parallel()
	r, regs, _, _ := newOPlusServerWithIdentities(t)

	// Registration approved but partner has NOT uploaded a public key yet.
	// Per [[feedback-no-stubs-real-wiring]] the field is emitted as "" —
	// fabricating sha256(agid) is forbidden.
	seedMatureApprovedRegistration(t, regs,
		"01970000-0000-7000-c000-000000000r15", "agid:test:r15:01")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/a2a/identities", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	got, _ := resp["identities"].([]any)
	row, _ := got[0].(map[string]any)
	fp, ok := row["key_fingerprint"].(string)
	if !ok {
		t.Fatalf("key_fingerprint missing or wrong type: %#v", row["key_fingerprint"])
	}
	if fp != "" {
		t.Errorf("key_fingerprint = %q; want empty (no identity on file → honest null per [[feedback-no-stubs-real-wiring]])", fp)
	}
	rotated, _ := row["rotated_at"].(string)
	if rotated != "" {
		t.Errorf("rotated_at = %q; want empty (no identity = no rotation timestamp)", rotated)
	}
}

// indexHex emits a 12-hex-digit zero-padded representation of i for use
// as a unique UUID-suffix in test invocations.
func indexHex(i int) string {
	const hexChars = "0123456789abcdef"
	const width = 12
	out := make([]byte, width)
	for j := width - 1; j >= 0; j-- {
		out[j] = hexChars[i&0xf]
		i >>= 4
	}
	return string(out)
}
