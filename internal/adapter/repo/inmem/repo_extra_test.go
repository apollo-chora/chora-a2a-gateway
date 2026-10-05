// Package inmem_test — repo_extra_test.go: extra coverage for the new
// repo methods (GetByAGID, BYOAKey, MCPConfig, InvocationRepo.Update +
// Get + ListByPartner).
package inmem_test

import (
	"testing"
	"time"

	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/repo/inmem"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/contract"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/invocation"
)

func TestRegistrationRepo_GetByAGID(t *testing.T) {
	t.Parallel()
	repo := inmem.NewRegistrationRepo()
	r := mustReg(t, "01970000-0000-7000-a000-000000000010")
	r.AGID = "agid:01970000-0000-7000-a000-000000000010:recommend:01"
	_ = repo.Put(r)
	got, err := repo.GetByAGID(r.AGID)
	if err != nil {
		t.Fatalf("GetByAGID: %v", err)
	}
	if got.ID != r.ID {
		t.Errorf("ID = %q", got.ID)
	}
	if _, err := repo.GetByAGID("agid:absent"); err == nil {
		t.Error("expected ErrNotFound for absent AGID")
	}
}

func TestContractRepo_GetByID(t *testing.T) {
	t.Parallel()
	repo := inmem.NewContractRepo()
	c, _ := contract.New(contract.NewParams{
		ID:         "01970000-0000-7000-d000-000000000050",
		PartnerID:  "01970000-0000-7000-a000-000000000050",
		AuthMethod: contract.AuthAPIKey,
		Capabilities: []contract.Capability{
			{Name: "x", Tier: contract.TierLow, RateLimitPerMin: 10},
		},
	})
	_ = repo.Put(c)
	got, err := repo.Get(c.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.PartnerID != c.PartnerID {
		t.Errorf("PartnerID = %q", got.PartnerID)
	}
	if _, err := repo.Get("absent"); err == nil {
		t.Error("expected ErrNotFound")
	}
}

func TestInvocationRepo_GetUpdateImmutability(t *testing.T) {
	t.Parallel()
	repo := inmem.NewInvocationRepo()
	i, _ := invocation.New(invocation.NewParams{
		ID:            "01970000-0000-7000-e000-000000000010",
		AGID:          "agid:p:c:01",
		PartnerID:     "01970000-0000-7000-a000-000000000060",
		Capability:    "x",
		CorrelationID: "01970000-0000-7000-c000-000000000010",
		Endpoint:      "https://a2a.chora.site/a2a/invoke#x",
	})
	_ = repo.Append(i)

	got, err := repo.Get(i.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.AGID != i.AGID {
		t.Errorf("AGID = %q", got.AGID)
	}
	if got.Endpoint != "https://a2a.chora.site/a2a/invoke#x" {
		t.Errorf("Endpoint = %q; want canonical capability URL persisted", got.Endpoint)
	}

	// Tamper the AGID — Update should reject.
	tampered := *i
	tampered.AGID = "agid:other:cap:01"
	if err := repo.Update(&tampered); err == nil {
		t.Error("expected immutability rejection on tampered AGID")
	}

	// Capability tamper.
	tampered = *i
	tampered.Capability = "y"
	if err := repo.Update(&tampered); err == nil {
		t.Error("expected immutability rejection on tampered Capability")
	}

	// CorrelationID tamper.
	tampered = *i
	tampered.CorrelationID = "01970000-0000-7000-c000-000000099999"
	if err := repo.Update(&tampered); err == nil {
		t.Error("expected immutability rejection on tampered CorrelationID")
	}

	// Update unknown ID.
	stranger, _ := invocation.New(invocation.NewParams{
		ID: "absent", AGID: "a", PartnerID: "p", Capability: "c", CorrelationID: "x",
	})
	if err := repo.Update(stranger); err == nil {
		t.Error("expected ErrNotFound on Update of absent invocation")
	}

	// Legitimate terminal-status update — should succeed.
	updated := *i
	_ = updated.Complete(0)
	if err := repo.Update(&updated); err != nil {
		t.Errorf("legitimate Update: %v", err)
	}
}

func TestInvocationRepo_ListSince_PreservesEndpoint(t *testing.T) {
	t.Parallel()
	repo := inmem.NewInvocationRepo()
	i, _ := invocation.New(invocation.NewParams{
		ID:            "01970000-0000-7000-e000-000000000020",
		AGID:          "agid:p:c:01",
		PartnerID:     "01970000-0000-7000-a000-000000000070",
		Capability:    "recommend_content",
		CorrelationID: "01970000-0000-7000-c000-000000000020",
		Endpoint:      "https://partner.example/a2a/v1/recommend_content",
	})
	if err := repo.Append(i); err != nil {
		t.Fatalf("Append: %v", err)
	}

	rows, err := repo.ListSince(time.Time{})
	if err != nil {
		t.Fatalf("ListSince: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d; want 1", len(rows))
	}
	if rows[0].Endpoint != "https://partner.example/a2a/v1/recommend_content" {
		t.Errorf("Endpoint = %q; want partner-domain URL preserved", rows[0].Endpoint)
	}
}

func TestBYOAKeyRepo_Lifecycle(t *testing.T) {
	t.Parallel()
	repo := inmem.NewBYOAKeyRepo()

	if _, err := repo.Get("t1", "openai"); err == nil {
		t.Error("expected ErrNotFound for missing entry")
	}

	entry := &inmem.BYOAKeyEntry{
		TenantID:       "t1",
		Provider:       "openai",
		Ciphertext:     []byte{1, 2, 3},
		KeyFingerprint: "abc",
		RotatedAt:      time.Now(),
	}
	_ = repo.Put(entry)

	got, err := repo.Get("t1", "openai")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.KeyFingerprint != "abc" {
		t.Errorf("KeyFingerprint = %q", got.KeyFingerprint)
	}

	if err := repo.SoftDelete("t1", "openai"); err != nil {
		t.Fatalf("SoftDelete: %v", err)
	}
	if _, err := repo.Get("t1", "openai"); err == nil {
		t.Error("expected ErrNotFound after SoftDelete")
	}

	if err := repo.SoftDelete("t1", "absent"); err == nil {
		t.Error("expected ErrNotFound on SoftDelete of absent")
	}
}

func TestMCPConfigRepo_Lifecycle(t *testing.T) {
	t.Parallel()
	repo := inmem.NewMCPConfigRepo()

	if _, err := repo.Get("t1"); err == nil {
		t.Error("expected ErrNotFound for missing config")
	}

	cfg := &inmem.MCPConfig{
		TenantID:     "t1",
		APIKeyHash:   "abc",
		AllowedTools: []string{"atom_search"},
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}
	_ = repo.Put(cfg)

	got, err := repo.Get("t1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.AllowedTools[0] != "atom_search" {
		t.Errorf("AllowedTools[0] = %q", got.AllowedTools[0])
	}
}
