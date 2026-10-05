// Package inmem_test exercises the new in-memory repos for partner
// registrations, contracts and invocations.
//
// Skeleton-level adapters; M12 swaps for Postgres repos in chora_a2a DB.
//
// CRITICAL invariants:
//   - RegistrationRepo stores by ID; ListByStatus filters non-deleted
//   - ContractRepo stores by ID; ListByPartner filters non-deleted
//   - InvocationRepo is append-only (audit log); ListByPartner filters non-deleted
//
// TDD RED phase — implementation does NOT yet exist.
package inmem_test

import (
	"testing"

	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/repo/inmem"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/contract"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/invocation"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/partner"
)

const (
	regIDA       = "01970000-0000-7000-a000-000000000001"
	regIDB       = "01970000-0000-7000-a000-000000000002"
	contractIDA  = "01970000-0000-7000-d000-000000000001"
	invocIDA     = "01970000-0000-7000-e000-000000000001"
	approverGCID = "01970000-0000-7000-9000-000000000099"
)

// -----------------------------------------------------------------------------
// RegistrationRepo
// -----------------------------------------------------------------------------

func TestRegistrationRepo_PutAndGet(t *testing.T) {
	t.Parallel()
	repo := inmem.NewRegistrationRepo()
	r := mustReg(t, regIDA)
	if err := repo.Put(r); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := repo.Get(regIDA)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != regIDA {
		t.Errorf("ID = %q", got.ID)
	}
}

func TestRegistrationRepo_GetNotFound(t *testing.T) {
	t.Parallel()
	repo := inmem.NewRegistrationRepo()
	if _, err := repo.Get("missing-id"); err == nil {
		t.Error("expected ErrNotFound; got nil")
	}
}

func TestRegistrationRepo_ListByStatus(t *testing.T) {
	t.Parallel()
	repo := inmem.NewRegistrationRepo()
	a := mustReg(t, regIDA)
	b := mustReg(t, regIDB)
	_, _ = b.Approve(partner.ApprovalParams{
		ApprovedByGCID: approverGCID,
		Tier:           partner.TierLow,
	})
	_ = repo.Put(a)
	_ = repo.Put(b)

	pending, err := repo.ListByStatus(partner.RegistrationPending)
	if err != nil {
		t.Fatalf("ListByStatus pending: %v", err)
	}
	if len(pending) != 1 || pending[0].ID != regIDA {
		t.Errorf("pending list = %v", pending)
	}

	approved, err := repo.ListByStatus(partner.RegistrationApproved)
	if err != nil {
		t.Fatalf("ListByStatus approved: %v", err)
	}
	if len(approved) != 1 || approved[0].ID != regIDB {
		t.Errorf("approved list = %v", approved)
	}
}

// -----------------------------------------------------------------------------
// ContractRepo
// -----------------------------------------------------------------------------

func TestContractRepo_PutListByPartner(t *testing.T) {
	t.Parallel()
	repo := inmem.NewContractRepo()
	c, _ := contract.New(contract.NewParams{
		ID:         contractIDA,
		PartnerID:  regIDA,
		AuthMethod: contract.AuthAPIKey,
		Capabilities: []contract.Capability{
			{Name: "x", Tier: contract.TierLow, RateLimitPerMin: 10},
		},
	})
	if err := repo.Put(c); err != nil {
		t.Fatalf("Put: %v", err)
	}
	list, err := repo.ListByPartner(regIDA)
	if err != nil {
		t.Fatalf("ListByPartner: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("list len = %d; want 1", len(list))
	}
}

func TestContractRepo_ListByPartner_FiltersSoftDeleted(t *testing.T) {
	t.Parallel()
	repo := inmem.NewContractRepo()
	c, _ := contract.New(contract.NewParams{
		ID:         contractIDA,
		PartnerID:  regIDA,
		AuthMethod: contract.AuthAPIKey,
		Capabilities: []contract.Capability{
			{Name: "x", Tier: contract.TierLow, RateLimitPerMin: 10},
		},
	})
	c.SoftDelete()
	_ = repo.Put(c)
	list, _ := repo.ListByPartner(regIDA)
	if len(list) != 0 {
		t.Errorf("soft-deleted contracts leaked: %d", len(list))
	}
}

// -----------------------------------------------------------------------------
// InvocationRepo (append-only)
// -----------------------------------------------------------------------------

func TestInvocationRepo_AppendAndListByPartner(t *testing.T) {
	t.Parallel()
	repo := inmem.NewInvocationRepo()
	i, _ := invocation.New(invocation.NewParams{
		ID:            invocIDA,
		AGID:          "agid:partner:cap:01",
		PartnerID:     regIDA,
		Capability:    "x",
		CorrelationID: "01970000-0000-7000-c000-000000000001",
	})
	if err := repo.Append(i); err != nil {
		t.Fatalf("Append: %v", err)
	}
	list, err := repo.ListByPartner(regIDA)
	if err != nil {
		t.Fatalf("ListByPartner: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("list len = %d; want 1", len(list))
	}
}

func TestInvocationRepo_AppendDuplicateRejected(t *testing.T) {
	t.Parallel()
	repo := inmem.NewInvocationRepo()
	i, _ := invocation.New(invocation.NewParams{
		ID:            invocIDA,
		AGID:          "agid:p:c:01",
		PartnerID:     regIDA,
		Capability:    "x",
		CorrelationID: "01970000-0000-7000-c000-000000000001",
	})
	_ = repo.Append(i)
	if err := repo.Append(i); err == nil {
		t.Error("expected duplicate-id error; got nil")
	}
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func mustReg(t *testing.T, id string) *partner.Registration {
	t.Helper()
	r, err := partner.NewRegistration(partner.RegistrationParams{
		ID:                 id,
		OrgName:            "Acme",
		ContactEmail:       "ops@acme.example",
		Capabilities:       []string{"recommend"},
		RequestedRateLimit: 100,
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	return r
}
