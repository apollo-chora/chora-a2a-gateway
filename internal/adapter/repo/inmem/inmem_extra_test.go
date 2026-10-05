// inmem_extra_test.go — additional coverage for the O+ listing endpoints that
// back the chora-gateway BFF read paths (Phase B7). Targets the ListAll
// (identities / contracts listings), ListByStatus soft-delete filter, the
// invocation append/update invariants, and ListSince ordering/filtering.
package inmem_test

import (
	"errors"
	"testing"
	"time"

	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/repo/inmem"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/contract"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/invocation"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/partner"
)

// -----------------------------------------------------------------------------
// RegistrationRepo.ListAll
// -----------------------------------------------------------------------------

func TestRegistrationRepo_ListAll_SortsByCreatedAt(t *testing.T) {
	t.Parallel()
	repo := inmem.NewRegistrationRepo()
	a := mustReg(t, regIDA)
	b := mustReg(t, regIDB)
	// Force a stable, non-equal CreatedAt ordering (a earlier than b).
	a.CreatedAt = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	b.CreatedAt = time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	_ = repo.Put(b)
	_ = repo.Put(a) // inserted out of order; ListAll must sort ascending

	list, err := repo.ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	if len(list) != 2 || list[0].ID != regIDA || list[1].ID != regIDB {
		t.Errorf("ListAll order = [%s, %s]; want [%s, %s]",
			firstName(list), lastName(list), regIDA, regIDB)
	}
}

func TestRegistrationRepo_ListAll_FiltersSoftDeleted(t *testing.T) {
	t.Parallel()
	repo := inmem.NewRegistrationRepo()
	live := mustReg(t, regIDA)
	deleted := mustReg(t, regIDB)
	now := time.Now().UTC()
	deleted.DeletedAt = &now
	_ = repo.Put(live)
	_ = repo.Put(deleted)

	list, err := repo.ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	if len(list) != 1 || list[0].ID != regIDA {
		t.Errorf("soft-deleted registrations leaked into ListAll: %+v", list)
	}
}

func TestRegistrationRepo_ListByStatus_FiltersSoftDeleted(t *testing.T) {
	t.Parallel()
	repo := inmem.NewRegistrationRepo()
	live := mustReg(t, regIDA)
	deleted := mustReg(t, regIDB)
	now := time.Now().UTC()
	deleted.DeletedAt = &now
	_ = repo.Put(live)
	_ = repo.Put(deleted)

	pending, err := repo.ListByStatus(partner.RegistrationPending)
	if err != nil {
		t.Fatalf("ListByStatus: %v", err)
	}
	if len(pending) != 1 || pending[0].ID != regIDA {
		t.Errorf("soft-deleted registration leaked into ListByStatus: %+v", pending)
	}
}

// -----------------------------------------------------------------------------
// ContractRepo.ListAll
// -----------------------------------------------------------------------------

func mustContract(t *testing.T, id, partnerID string) *contract.Contract {
	t.Helper()
	c, err := contract.New(contract.NewParams{
		ID:         id,
		PartnerID:  partnerID,
		AuthMethod: contract.AuthAPIKey,
		Capabilities: []contract.Capability{
			{Name: "recommend_content", Tier: contract.TierLow, RateLimitPerMin: 10},
		},
	})
	if err != nil {
		t.Fatalf("seed contract: %v", err)
	}
	return c
}

func TestContractRepo_ListAll_FiltersSoftDeleted(t *testing.T) {
	t.Parallel()
	repo := inmem.NewContractRepo()
	live := mustContract(t, contractIDA, regIDA)
	deleted := mustContract(t, "01970000-0000-7000-d000-000000000002", regIDB)
	deleted.SoftDelete()
	_ = repo.Put(live)
	_ = repo.Put(deleted)

	list, err := repo.ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	if len(list) != 1 || list[0].ID != contractIDA {
		t.Errorf("soft-deleted contract leaked into ListAll: %+v", list)
	}
}

// -----------------------------------------------------------------------------
// InvocationRepo — append-only + ListSince
// -----------------------------------------------------------------------------

func TestInvocationRepo_ListSince_FiltersBeforeSinceAndOrdersDescending(t *testing.T) {
	t.Parallel()
	repo := inmem.NewInvocationRepo()
	old, _ := invocation.New(invocation.NewParams{
		ID:            invocIDA,
		AGID:          "agid:p:c:01",
		PartnerID:     regIDA,
		Capability:    "x",
		CorrelationID: "01970000-0000-7000-c000-000000000001",
	})
	newer, _ := invocation.New(invocation.NewParams{
		ID:            "01970000-0000-7000-e000-000000000002",
		AGID:          "agid:p:c:02",
		PartnerID:     regIDA,
		Capability:    "x",
		CorrelationID: "01970000-0000-7000-c000-000000000002",
	})
	old.StartedAt = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	newer.StartedAt = time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	_ = repo.Append(old)
	_ = repo.Append(newer)

	// since = Feb 1 → only `newer` qualifies.
	list, err := repo.ListSince(time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("ListSince: %v", err)
	}
	if len(list) != 1 || list[0].ID != "01970000-0000-7000-e000-000000000002" {
		t.Errorf("ListSince(since) = %+v; want only the newer invocation", list)
	}

	// zero since → full log, newest first (descending by StartedAt).
	all, err := repo.ListSince(time.Time{})
	if err != nil {
		t.Fatalf("ListSince(zero): %v", err)
	}
	if len(all) != 2 || all[0].ID != "01970000-0000-7000-e000-000000000002" || all[1].ID != invocIDA {
		t.Errorf("ListSince(zero) order = [%s, %s]; want newest-first", firstName(all), lastName(all))
	}
}

func TestInvocationRepo_Update_RejectsImmutableFieldChanges(t *testing.T) {
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

	mutated := *i
	mutated.AGID = "agid:other:99"
	if err := repo.Update(&mutated); err == nil {
		t.Error("expected an error when AGID changes on Update; got nil")
	}

	mutated = *i
	mutated.Capability = "different"
	if err := repo.Update(&mutated); err == nil {
		t.Error("expected an error when Capability changes on Update; got nil")
	}

	mutated = *i
	mutated.CorrelationID = "another-corr"
	if err := repo.Update(&mutated); err == nil {
		t.Error("expected an error when CorrelationID changes on Update; got nil")
	}

	// Unknown id → ErrNotFound.
	ghost, _ := invocation.New(invocation.NewParams{
		ID:            "01970000-0000-7000-e000-0000000000ff",
		AGID:          "agid:p:c:01",
		PartnerID:     regIDA,
		Capability:    "x",
		CorrelationID: "01970000-0000-7000-c000-000000000001",
	})
	if err := repo.Update(ghost); err == nil || !errors.Is(err, inmem.ErrNotFound) {
		t.Errorf("Update(unknown id) = %v; want ErrNotFound", err)
	}
}

func firstName[T any](s []*T) string {
	if len(s) == 0 {
		return ""
	}
	return stringFromAny(s[0])
}

func lastName[T any](s []*T) string {
	if len(s) == 0 {
		return ""
	}
	return stringFromAny(s[len(s)-1])
}

func stringFromAny(v any) string {
	switch x := v.(type) {
	case *partner.Registration:
		return x.ID
	case *contract.Contract:
		return x.ID
	case *invocation.Invocation:
		return x.ID
	default:
		return ""
	}
}
