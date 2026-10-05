// scan_rows_test.go — drives the LIST-row scanners (scanRegistrationRows /
// scanContractRows / scanInvocationRows) through their aggregate store methods
// with populated + erroring row sets. The single-row scanners (scanRegistration
// / scanContract / scanInvocation) already have happy-path coverage in
// repo_test.go; this file adds the multi-row iteration, ErrNoRows-skip,
// mid-scan error, and rows.Err() error branches so the row helpers reach full
// coverage.
package pg_test

import (
	"context"
	"errors"
	"testing"
	"time"

	chorapg "github.com/apollo-chora/chora-a2a-gateway/internal/adapter/pg"
	pgrepo "github.com/apollo-chora/chora-a2a-gateway/internal/adapter/repo/pg"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/contract"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/invocation"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/partner"
)

// scriptRows is a configurable chorapg.Rows used to drive the *scan*Rows
// helpers directly through a store's Query path. Each entry in scans is one
// row; err is returned from Err() after iteration.
type scriptRows struct {
	scans []func(dest ...any) error
	cur   int
	err   error
}

func (r *scriptRows) Next() bool { return r.cur < len(r.scans) }
func (r *scriptRows) Scan(dest ...any) error {
	if r.cur >= len(r.scans) {
		return errors.New("scriptRows: no more rows")
	}
	fn := r.scans[r.cur]
	r.cur++
	return fn(dest...)
}
func (r *scriptRows) Close()     {}
func (r *scriptRows) Err() error { return r.err }

// scriptQuerier returns a fixed Rows from every Query; QueryRow/Exec are
// unreachable on the List paths under test. Set queryErr to exercise the
// Query() failure branch.
type scriptQuerier struct {
	rows     chorapg.Rows
	queryErr error
}

func (s *scriptQuerier) Exec(_ context.Context, _ string, _ ...any) error { return nil }
func (s *scriptQuerier) QueryRow(_ context.Context, _ string, _ ...any) chorapg.Row {
	return &stubRow{err: chorapg.ErrNoRows}
}
func (s *scriptQuerier) Query(_ context.Context, _ string, _ ...any) (chorapg.Rows, error) {
	if s.queryErr != nil {
		return nil, s.queryErr
	}
	return s.rows, nil
}

// registrationScanner builds a row-scanner mirroring registrationSelectColumns
// (21 dests). Suspension + DNS fields are left nil.
func registrationScanner(id, org, email string, state partner.RegistrationState) func(dest ...any) error {
	return func(dest ...any) error {
		*(dest[0].(*string)) = id
		*(dest[1].(*string)) = org
		*(dest[2].(*string)) = email
		*(dest[3].(*[]string)) = []string{"recommend_content"}
		*(dest[4].(*int)) = 100
		*(dest[5].(*string)) = string(state)
		*(dest[6].(**string)) = nil
		*(dest[7].(**string)) = nil
		*(dest[8].(**string)) = nil
		*(dest[9].(**string)) = nil
		*(dest[10].(**time.Time)) = nil
		*(dest[11].(**string)) = nil
		*(dest[12].(**time.Time)) = nil
		*(dest[13].(**string)) = nil
		*(dest[14].(**string)) = nil
		*(dest[15].(**string)) = nil
		*(dest[16].(*bool)) = false
		*(dest[17].(**time.Time)) = nil
		*(dest[18].(*time.Time)) = time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
		*(dest[19].(*time.Time)) = time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
		*(dest[20].(**time.Time)) = nil
		return nil
	}
}

func TestRegistrationStore_ListAll_IteratesMultipleRows(t *testing.T) {
	t.Parallel()
	rows := &scriptRows{scans: []func(dest ...any) error{
		registrationScanner("reg-1", "Acme", "ops@acme.example", partner.RegistrationApproved),
		registrationScanner("reg-2", "Beta", "ops@beta.example", partner.RegistrationPending),
	}}
	repo := pgrepo.NewRegistrationStore(&scriptQuerier{rows: rows}, "tenant-1")

	out, err := repo.ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("ListAll = %d rows; want 2", len(out))
	}
	if out[0].ID != "reg-1" || out[0].State != partner.RegistrationApproved {
		t.Errorf("row[0] = %+v", out[0])
	}
	if out[1].ID != "reg-2" || out[1].State != partner.RegistrationPending {
		t.Errorf("row[1] = %+v", out[1])
	}
}

// ErrNoRows during iteration is skipped (soft-delete tombstone rows collapse).
func TestRegistrationStore_ListByStatus_SkipsErrNoRowsRows(t *testing.T) {
	t.Parallel()
	rows := &scriptRows{scans: []func(dest ...any) error{
		func(dest ...any) error { return chorapg.ErrNoRows },
		registrationScanner("reg-3", "Gamma", "ops@gamma.example", partner.RegistrationSuspended),
	}}
	repo := pgrepo.NewRegistrationStore(&scriptQuerier{rows: rows}, "tenant-1")

	out, err := repo.ListByStatus(partner.RegistrationSuspended)
	if err != nil {
		t.Fatalf("ListByStatus: %v", err)
	}
	if len(out) != 1 || out[0].ID != "reg-3" {
		t.Errorf("ListByStatus = %+v; want single reg-3", out)
	}
}

// A mid-scan error (non-ErrNoRows) aborts iteration and surfaces the error.
func TestRegistrationStore_ListAll_ScanErrorAborts(t *testing.T) {
	t.Parallel()
	rows := &scriptRows{scans: []func(dest ...any) error{
		registrationScanner("reg-ok", "Ok", "ok@example", partner.RegistrationApproved),
		func(dest ...any) error { return errors.New("boom") },
	}}
	repo := pgrepo.NewRegistrationStore(&scriptQuerier{rows: rows}, "tenant-1")

	if _, err := repo.ListAll(); err == nil {
		t.Fatal("expected mid-scan error to propagate")
	}
}

// rows.Err() after iteration propagates.
func TestRegistrationStore_ListAll_RowsErrPropagates(t *testing.T) {
	t.Parallel()
	rows := &scriptRows{
		scans: []func(dest ...any) error{
			registrationScanner("reg-err", "Err", "e@example", partner.RegistrationApproved),
		},
		err: errors.New("rows.Err died"),
	}
	repo := pgrepo.NewRegistrationStore(&scriptQuerier{rows: rows}, "tenant-1")

	if _, err := repo.ListAll(); err == nil {
		t.Fatal("expected rows.Err() to propagate")
	}
}

func contractScanner(id, partnerID string, auth contract.AuthMethod) func(dest ...any) error {
	return func(dest ...any) error {
		*(dest[0].(*string)) = id
		*(dest[1].(*string)) = partnerID
		*(dest[2].(*string)) = string(auth)
		*(dest[3].(*[]byte)) = []byte(`[{"name":"recommend_content","tier":"medium","rate_limit_per_min":600}]`)
		*(dest[4].(*int)) = 1
		*(dest[5].(**string)) = nil
		*(dest[6].(**time.Time)) = nil
		*(dest[7].(*time.Time)) = time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
		*(dest[8].(*time.Time)) = time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
		*(dest[9].(**time.Time)) = nil
		return nil
	}
}

func TestContractStore_ListByPartner_IteratesRows(t *testing.T) {
	t.Parallel()
	rows := &scriptRows{scans: []func(dest ...any) error{
		contractScanner("c-1", "p-1", contract.AuthAPIKey),
		contractScanner("c-2", "p-1", contract.AuthOAuth2),
	}}
	repo := pgrepo.NewContractStore(&scriptQuerier{rows: rows}, "tenant-1")

	out, err := repo.ListByPartner("p-1")
	if err != nil {
		t.Fatalf("ListByPartner: %v", err)
	}
	if len(out) != 2 || out[0].ID != "c-1" || out[1].ID != "c-2" {
		t.Fatalf("ListByPartner = %+v", out)
	}
	if out[0].AuthMethod != contract.AuthAPIKey || len(out[0].Capabilities) != 1 {
		t.Errorf("row[0] = %+v", out[0])
	}
}

func TestContractStore_ListAll_ErrNoRowsSkipped(t *testing.T) {
	t.Parallel()
	rows := &scriptRows{scans: []func(dest ...any) error{
		func(dest ...any) error { return chorapg.ErrNoRows },
		contractScanner("c-3", "p-2", contract.AuthAPIKey),
	}}
	repo := pgrepo.NewContractStore(&scriptQuerier{rows: rows}, "tenant-1")

	out, err := repo.ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	if len(out) != 1 || out[0].ID != "c-3" {
		t.Errorf("ListAll = %+v; want single c-3", out)
	}
}

func TestContractStore_ListByPartner_ScanErrorAborts(t *testing.T) {
	t.Parallel()
	rows := &scriptRows{scans: []func(dest ...any) error{
		func(dest ...any) error { return errors.New("bad caps json") },
	}}
	repo := pgrepo.NewContractStore(&scriptQuerier{rows: rows}, "tenant-1")

	if _, err := repo.ListByPartner("p-1"); err == nil {
		t.Fatal("expected scan error to propagate")
	}
}

func invocationScanner(id, status string) func(dest ...any) error {
	started := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	return func(dest ...any) error {
		*(dest[0].(*string)) = id
		*(dest[1].(*string)) = "agid:partner:cap:01"
		*(dest[2].(*string)) = "p-1"
		*(dest[3].(*string)) = "recommend_content"
		*(dest[4].(*string)) = "corr-001"
		*(dest[5].(*string)) = status
		*(dest[6].(*int)) = 0
		*(dest[7].(*int)) = 0
		*(dest[8].(*string)) = ""
		*(dest[9].(*time.Time)) = started
		*(dest[10].(**time.Time)) = nil
		*(dest[11].(*string)) = ""
		*(dest[12].(*string)) = ""
		return nil
	}
}

func TestInvocationStore_ListByPartner_IteratesRows(t *testing.T) {
	t.Parallel()
	rows := &scriptRows{scans: []func(dest ...any) error{
		invocationScanner("inv-1", "completed"),
		invocationScanner("inv-2", "failed"),
	}}
	repo := pgrepo.NewInvocationStore(&scriptQuerier{rows: rows}, "tenant-1")

	out, err := repo.ListByPartner("p-1")
	if err != nil {
		t.Fatalf("ListByPartner: %v", err)
	}
	if len(out) != 2 || out[0].ID != "inv-1" || out[1].ID != "inv-2" {
		t.Fatalf("ListByPartner = %+v", out)
	}
	if out[0].Status != invocation.StatusCompleted || out[1].Status != invocation.StatusFailed {
		t.Errorf("statuses = %q, %q", out[0].Status, out[1].Status)
	}
}

func TestInvocationStore_ListSince_ErrNoRowsSkipped(t *testing.T) {
	t.Parallel()
	rows := &scriptRows{scans: []func(dest ...any) error{
		func(dest ...any) error { return chorapg.ErrNoRows },
		invocationScanner("inv-3", "started"),
	}}
	repo := pgrepo.NewInvocationStore(&scriptQuerier{rows: rows}, "tenant-1")

	out, err := repo.ListSince(time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("ListSince: %v", err)
	}
	if len(out) != 1 || out[0].ID != "inv-3" {
		t.Errorf("ListSince = %+v; want single inv-3", out)
	}
}

func TestInvocationStore_ListSince_ScanErrorAborts(t *testing.T) {
	t.Parallel()
	rows := &scriptRows{scans: []func(dest ...any) error{
		func(dest ...any) error { return errors.New("scan failed") },
	}}
	repo := pgrepo.NewInvocationStore(&scriptQuerier{rows: rows}, "tenant-1")

	if _, err := repo.ListSince(time.Time{}); err == nil {
		t.Fatal("expected scan error to propagate")
	}
}

// Query() error branches on the List methods must propagate the wrapped error.
func TestRepoList_QueryErrorBranches(t *testing.T) {
	t.Parallel()
	qErr := errors.New("query down")

	regRepo := pgrepo.NewRegistrationStore(&scriptQuerier{queryErr: qErr}, "tenant-1")
	if _, err := regRepo.ListAll(); err == nil {
		t.Error("RegistrationStore.ListAll must propagate Query error")
	}

	ctRepo := pgrepo.NewContractStore(&scriptQuerier{queryErr: qErr}, "tenant-1")
	if _, err := ctRepo.ListAll(); err == nil {
		t.Error("ContractStore.ListAll must propagate Query error")
	}

	invRepo := pgrepo.NewInvocationStore(&scriptQuerier{queryErr: qErr}, "tenant-1")
	if _, err := invRepo.ListByPartner("p"); err == nil {
		t.Error("InvocationStore.ListByPartner must propagate Query error")
	}
	if _, err := invRepo.ListSince(time.Now().Add(-time.Hour)); err == nil {
		t.Error("InvocationStore.ListSince (non-zero) must propagate Query error")
	}
	if _, err := invRepo.ListSince(time.Time{}); err == nil {
		t.Error("InvocationStore.ListSince (zero) must propagate Query error")
	}
}

// ----------------------------------------------------------------------------
// nil aggregate guards already asserted in repo_test.go (Put/Append); the rows
// helpers above are the target of this file.
// -----------------------------------------------------------------------------
