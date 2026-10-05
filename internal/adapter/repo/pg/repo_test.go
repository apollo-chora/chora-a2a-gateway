// Package pg_test — unit tests for the pgx-backed RegistrationStore /
// ContractStore / InvocationStore implementations.
//
// Per [[feedback-no-stubs-real-wiring]]: live-DB integration tests must
// run against a real Postgres via the `integration` build tag (see
// integration_test.go in this directory). The unit tests below use a stub
// Querier to assert the SQL contract — column lists, bind args, soft-delete
// filtering, AGID ≠ GCID invariant.
//
// CRITICAL invariants asserted here:
//
//   - Soft-delete: ListAll / ListByPartner / ListByStatus / ListSince
//     queries default to `WHERE deleted_at IS NULL`.
//   - AGID ≠ GCID: emitted SQL MUST NOT contain a `gcid` column.
//   - InvocationStore.Append uses INSERT (rejects ON CONFLICT to keep the
//     audit log append-only); Update uses UPDATE WHERE id = $... and never
//     mutates agid / capability / correlation_id / started_at columns.
package pg_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	chorapg "github.com/apollo-chora/chora-a2a-gateway/internal/adapter/pg"
	pgrepo "github.com/apollo-chora/chora-a2a-gateway/internal/adapter/repo/pg"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/contract"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/invocation"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/partner"
)

// -----------------------------------------------------------------------------
// stubs
// -----------------------------------------------------------------------------

// recordedCall captures one Exec / Query / QueryRow call for SQL assertions.
type recordedCall struct {
	op   string
	sql  string
	args []any
}

type stubQuerier struct {
	calls []recordedCall

	// execErr is returned by every Exec.
	execErr error

	// rowScanners is a FIFO queue — each QueryRow consumes one scanner.
	// When empty, return ErrNoRows.
	rowScanners []func(dest ...any) error

	// rowsScanners is a FIFO queue — each Query consumes one. nil scanners
	// produce no rows (Next → false).
	rowsScanners []*stubRows

	// queryErr is returned by every Query.
	queryErr error
}

func (s *stubQuerier) Exec(_ context.Context, sql string, args ...any) error {
	s.calls = append(s.calls, recordedCall{op: "Exec", sql: sql, args: args})
	return s.execErr
}

func (s *stubQuerier) QueryRow(_ context.Context, sql string, args ...any) chorapg.Row {
	s.calls = append(s.calls, recordedCall{op: "QueryRow", sql: sql, args: args})
	if len(s.rowScanners) == 0 {
		return &stubRow{err: chorapg.ErrNoRows}
	}
	fn := s.rowScanners[0]
	s.rowScanners = s.rowScanners[1:]
	return &stubRow{scan: fn}
}

func (s *stubQuerier) Query(_ context.Context, sql string, args ...any) (chorapg.Rows, error) {
	s.calls = append(s.calls, recordedCall{op: "Query", sql: sql, args: args})
	if s.queryErr != nil {
		return nil, s.queryErr
	}
	if len(s.rowsScanners) == 0 {
		return &stubRows{}, nil
	}
	r := s.rowsScanners[0]
	s.rowsScanners = s.rowsScanners[1:]
	if r == nil {
		return &stubRows{}, nil
	}
	return r, nil
}

type stubRow struct {
	scan func(dest ...any) error
	err  error
}

func (r *stubRow) Scan(dest ...any) error {
	if r.scan != nil {
		return r.scan(dest...)
	}
	return r.err
}

type stubRows struct {
	scans  []func(dest ...any) error
	cursor int
	closed bool
}

func (r *stubRows) Next() bool { return r.cursor < len(r.scans) }
func (r *stubRows) Scan(dest ...any) error {
	if r.cursor >= len(r.scans) {
		return errors.New("stubRows: no more rows")
	}
	fn := r.scans[r.cursor]
	r.cursor++
	return fn(dest...)
}
func (r *stubRows) Close()     { r.closed = true }
func (r *stubRows) Err() error { return nil }

// findCall returns the first recordedCall whose SQL contains the substring.
// Returns nil + false when not found.
func findCall(s *stubQuerier, substr string) (*recordedCall, bool) {
	for i := range s.calls {
		if strings.Contains(s.calls[i].sql, substr) {
			return &s.calls[i], true
		}
	}
	return nil, false
}

func assertNoGcidColumn(t *testing.T, sql string) {
	t.Helper()
	lower := strings.ToLower(sql)
	if strings.Contains(lower, "gcid") &&
		!strings.Contains(lower, "approved_by_gcid") &&
		!strings.Contains(lower, "suspended_by_gcid") {
		t.Errorf("SQL leaks a gcid column reference (CLAUDE.md §1 invariant). SQL:\n%s", sql)
	}
}

// -----------------------------------------------------------------------------
// RegistrationStore
// -----------------------------------------------------------------------------

func TestRegistrationStore_Put_EmitsUpsertSQL(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{}
	tenantID := uuid.NewString()
	repo := pgrepo.NewRegistrationStore(q, tenantID)

	reg, err := partner.NewRegistration(partner.RegistrationParams{
		ID:                 "01970000-0000-7000-a000-000000000001",
		OrgName:            "Acme",
		ContactEmail:       "ops@acme.example",
		Capabilities:       []string{"recommend_content"},
		RequestedRateLimit: 100,
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := repo.Put(reg); err != nil {
		t.Fatalf("Put: %v", err)
	}
	call, ok := findCall(q, "partner_registrations")
	if !ok {
		t.Fatalf("expected INSERT INTO partner_registrations; calls: %v", q.calls)
	}
	if !strings.Contains(call.sql, "ON CONFLICT") {
		t.Errorf("expected UPSERT (ON CONFLICT) in Put SQL; got:\n%s", call.sql)
	}
	assertNoGcidColumn(t, call.sql)
	// id first, tenant_id second.
	if call.args[0] != reg.ID {
		t.Errorf("arg[0] = %v; want id %q", call.args[0], reg.ID)
	}
	if call.args[1] != tenantID {
		t.Errorf("arg[1] = %v; want tenant %q", call.args[1], tenantID)
	}
}

func TestRegistrationStore_Get_ReturnsErrNotFound_OnMiss(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{}
	repo := pgrepo.NewRegistrationStore(q, uuid.NewString())
	if _, err := repo.Get("absent"); !errors.Is(err, pgrepo.ErrNotFound) {
		t.Fatalf("expected ErrNotFound on miss; got %v", err)
	}
}

func TestRegistrationStore_ListAll_FiltersSoftDeleted(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		rowsScanners: []*stubRows{{scans: nil}},
	}
	repo := pgrepo.NewRegistrationStore(q, uuid.NewString())
	if _, err := repo.ListAll(); err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	call, ok := findCall(q, "FROM partner_registrations")
	if !ok {
		t.Fatalf("expected SELECT FROM partner_registrations; calls: %+v", q.calls)
	}
	if !strings.Contains(call.sql, "deleted_at IS NULL") {
		t.Errorf("ListAll must filter deleted_at IS NULL. SQL:\n%s", call.sql)
	}
}

func TestRegistrationStore_ListByStatus_FiltersOnState(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{rowsScanners: []*stubRows{{}}}
	repo := pgrepo.NewRegistrationStore(q, uuid.NewString())
	if _, err := repo.ListByStatus(partner.RegistrationPending); err != nil {
		t.Fatalf("ListByStatus: %v", err)
	}
	call, ok := findCall(q, "FROM partner_registrations")
	if !ok {
		t.Fatalf("expected SELECT FROM partner_registrations")
	}
	if !strings.Contains(call.sql, "state =") {
		t.Errorf("ListByStatus must filter on state column. SQL:\n%s", call.sql)
	}
	if !strings.Contains(call.sql, "deleted_at IS NULL") {
		t.Errorf("ListByStatus must filter deleted_at IS NULL. SQL:\n%s", call.sql)
	}
}

func TestRegistrationStore_GetByAGID_FiltersAGID(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{}
	repo := pgrepo.NewRegistrationStore(q, uuid.NewString())
	_, _ = repo.GetByAGID("agid:test:01")
	call, ok := findCall(q, "FROM partner_registrations")
	if !ok {
		t.Fatalf("expected SELECT FROM partner_registrations; calls: %+v", q.calls)
	}
	if !strings.Contains(call.sql, "agid =") {
		t.Errorf("GetByAGID must filter on agid column. SQL:\n%s", call.sql)
	}
	if !strings.Contains(call.sql, "deleted_at IS NULL") {
		t.Errorf("GetByAGID must filter deleted_at IS NULL. SQL:\n%s", call.sql)
	}
}

// -----------------------------------------------------------------------------
// ContractStore
// -----------------------------------------------------------------------------

func TestContractStore_Put_EmitsUpsertSQL(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{}
	tenantID := uuid.NewString()
	repo := pgrepo.NewContractStore(q, tenantID)

	c, err := contract.New(contract.NewParams{
		ID:         "01970000-0000-7000-c000-000000000c01",
		PartnerID:  "01970000-0000-7000-c000-000000000p01",
		AuthMethod: contract.AuthAPIKey,
		Capabilities: []contract.Capability{
			{Name: "recommend_content", Tier: contract.TierMedium, RateLimitPerMin: 600},
		},
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := repo.Put(c); err != nil {
		t.Fatalf("Put: %v", err)
	}
	call, ok := findCall(q, "a2a_contracts")
	if !ok {
		t.Fatalf("expected INSERT INTO a2a_contracts; calls: %v", q.calls)
	}
	if !strings.Contains(call.sql, "ON CONFLICT") {
		t.Errorf("expected UPSERT (ON CONFLICT) in Put SQL")
	}
	assertNoGcidColumn(t, call.sql)
	if call.args[0] != c.ID {
		t.Errorf("arg[0] = %v; want id %q", call.args[0], c.ID)
	}
}

func TestContractStore_ListByPartner_FiltersSoftDeletedAndPartner(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{rowsScanners: []*stubRows{{}}}
	repo := pgrepo.NewContractStore(q, uuid.NewString())
	if _, err := repo.ListByPartner("p1"); err != nil {
		t.Fatalf("ListByPartner: %v", err)
	}
	call, ok := findCall(q, "FROM a2a_contracts")
	if !ok {
		t.Fatalf("expected SELECT FROM a2a_contracts")
	}
	if !strings.Contains(call.sql, "deleted_at IS NULL") {
		t.Errorf("ListByPartner must filter deleted_at IS NULL")
	}
	if !strings.Contains(call.sql, "partner_id =") {
		t.Errorf("ListByPartner must filter partner_id")
	}
}

func TestContractStore_ListAll_FiltersSoftDeleted(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{rowsScanners: []*stubRows{{}}}
	repo := pgrepo.NewContractStore(q, uuid.NewString())
	if _, err := repo.ListAll(); err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	call, _ := findCall(q, "FROM a2a_contracts")
	if call == nil || !strings.Contains(call.sql, "deleted_at IS NULL") {
		t.Errorf("ListAll must filter deleted_at IS NULL")
	}
}

// -----------------------------------------------------------------------------
// InvocationStore (append-only)
// -----------------------------------------------------------------------------

func TestInvocationStore_Append_EmitsInsertSQL(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{}
	tenantID := uuid.NewString()
	repo := pgrepo.NewInvocationStore(q, tenantID)

	i, err := invocation.New(invocation.NewParams{
		ID:            "01970000-0000-7000-e000-000000000001",
		AGID:          "agid:partner:cap:01",
		PartnerID:     "01970000-0000-7000-c000-000000000p01",
		Capability:    "recommend_content",
		CorrelationID: "corr-001",
		Endpoint:      "https://a2a.chora.site/a2a/invoke#recommend_content",
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := repo.Append(i); err != nil {
		t.Fatalf("Append: %v", err)
	}
	call, ok := findCall(q, "INSERT INTO a2a_invocations")
	if !ok {
		t.Fatalf("expected INSERT INTO a2a_invocations; calls: %+v", q.calls)
	}
	if strings.Contains(call.sql, "ON CONFLICT") {
		t.Errorf("Append must NOT silently merge — audit log is append-only.\nSQL:\n%s", call.sql)
	}
	if call.args[0] != i.ID {
		t.Errorf("arg[0] = %v; want id %q", call.args[0], i.ID)
	}
}

func TestInvocationStore_Update_DoesNotMutateImmutableColumns(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{}
	repo := pgrepo.NewInvocationStore(q, uuid.NewString())
	i, _ := invocation.New(invocation.NewParams{
		ID:            "01970000-0000-7000-e000-000000000002",
		AGID:          "agid:p:c:01",
		PartnerID:     "01970000-0000-7000-c000-000000000p01",
		Capability:    "recommend_content",
		CorrelationID: "corr-002",
	})
	_ = i.Complete(128)
	if err := repo.Update(i); err != nil {
		t.Fatalf("Update: %v", err)
	}
	call, ok := findCall(q, "UPDATE a2a_invocations")
	if !ok {
		t.Fatalf("expected UPDATE a2a_invocations; calls: %+v", q.calls)
	}
	lower := strings.ToLower(call.sql)
	// SET clause MUST NOT touch agid / capability / correlation_id / started_at
	// (the db trigger would reject these; the repo MUST stay correct by
	// construction).
	setIdx := strings.Index(lower, "set ")
	if setIdx < 0 {
		t.Fatalf("UPDATE missing SET clause")
	}
	setClause := lower[setIdx:]
	forbidden := []string{"agid =", "capability =", "correlation_id =", "started_at ="}
	for _, c := range forbidden {
		if strings.Contains(setClause, c) {
			t.Errorf("UPDATE SET clause mutates immutable column %q.\nSQL:\n%s", c, call.sql)
		}
	}
}

func TestInvocationStore_ListSince_FiltersByStartedAt(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{rowsScanners: []*stubRows{{}}}
	repo := pgrepo.NewInvocationStore(q, uuid.NewString())
	since := time.Now().Add(-1 * time.Hour).UTC()
	if _, err := repo.ListSince(since); err != nil {
		t.Fatalf("ListSince: %v", err)
	}
	call, ok := findCall(q, "FROM a2a_invocations")
	if !ok {
		t.Fatalf("expected SELECT FROM a2a_invocations")
	}
	if !strings.Contains(call.sql, "started_at >=") {
		t.Errorf("ListSince must filter started_at >= $...; SQL:\n%s", call.sql)
	}
	// args MUST include the cutoff time (we accept argument 1 = since).
	found := false
	for _, a := range call.args {
		if tt, ok := a.(time.Time); ok && tt.Equal(since) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("ListSince bind args do not contain `since`; args=%v", call.args)
	}
}

func TestInvocationStore_ListSince_ZeroReturnsAll(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{rowsScanners: []*stubRows{{}}}
	repo := pgrepo.NewInvocationStore(q, uuid.NewString())
	if _, err := repo.ListSince(time.Time{}); err != nil {
		t.Fatalf("ListSince(zero): %v", err)
	}
	call, _ := findCall(q, "FROM a2a_invocations")
	if call == nil {
		t.Fatalf("expected SELECT FROM a2a_invocations")
	}
	// Zero since → no started_at filter clause.
	if strings.Contains(call.sql, "started_at >=") {
		t.Errorf("zero `since` should omit started_at >= filter; SQL:\n%s", call.sql)
	}
}

func TestInvocationStore_ListByPartner_BindsPartnerID(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{rowsScanners: []*stubRows{{}}}
	repo := pgrepo.NewInvocationStore(q, uuid.NewString())
	if _, err := repo.ListByPartner("p1"); err != nil {
		t.Fatalf("ListByPartner: %v", err)
	}
	call, ok := findCall(q, "FROM a2a_invocations")
	if !ok {
		t.Fatalf("expected SELECT FROM a2a_invocations")
	}
	if !strings.Contains(call.sql, "partner_id =") {
		t.Errorf("ListByPartner must filter partner_id; SQL:\n%s", call.sql)
	}
}

// -----------------------------------------------------------------------------
// PortAssertions — compile-time: every pg type satisfies the matching port
// interface in internal/adapter/repo/ports.go.
// -----------------------------------------------------------------------------

func TestPortAssertions(t *testing.T) {
	t.Parallel()
	// Compile-time assertions; runtime no-op.
	_ = pgrepo.NewRegistrationStore((*nullQuerier)(nil), "")
	_ = pgrepo.NewContractStore((*nullQuerier)(nil), "")
	_ = pgrepo.NewInvocationStore((*nullQuerier)(nil), "")
}

// nullQuerier is the smallest possible Querier — used only for type assertions.
type nullQuerier struct{}

func (*nullQuerier) Exec(_ context.Context, _ string, _ ...any) error { return nil }
func (*nullQuerier) QueryRow(_ context.Context, _ string, _ ...any) chorapg.Row {
	return &stubRow{err: chorapg.ErrNoRows}
}
func (*nullQuerier) Query(_ context.Context, _ string, _ ...any) (chorapg.Rows, error) {
	return &stubRows{}, nil
}

// -----------------------------------------------------------------------------
// scan-path coverage — drives Get/ListAll through stub Row + Rows scanners.
// -----------------------------------------------------------------------------

func TestRegistrationStore_Get_ScansRowIntoAggregate(t *testing.T) {
	t.Parallel()
	id := "01970000-0000-7000-a000-000000000abc"
	createdAt := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	q := &stubQuerier{
		rowScanners: []func(dest ...any) error{
			func(dest ...any) error {
				// Mirrors registrationSelectColumns ordering.
				*(dest[0].(*string)) = id
				*(dest[1].(*string)) = "Acme"
				*(dest[2].(*string)) = "ops@acme.example"
				*(dest[3].(*[]string)) = []string{"recommend_content"}
				*(dest[4].(*int)) = 100
				*(dest[5].(*string)) = "approved"
				tier := "medium"
				*(dest[6].(**string)) = &tier
				agid := "agid:test:01"
				*(dest[7].(**string)) = &agid
				hash := strings.Repeat("a", 64)
				*(dest[8].(**string)) = &hash
				gcid := "01970000-0000-7000-9000-0000000000aa"
				*(dest[9].(**string)) = &gcid
				approvedAt := createdAt
				*(dest[10].(**time.Time)) = &approvedAt
				// suspended_by_gcid + suspended_at + suspend_reason nil
				*(dest[11].(**string)) = nil
				*(dest[12].(**time.Time)) = nil
				*(dest[13].(**string)) = nil
				// partner_domain + dns
				*(dest[14].(**string)) = nil
				*(dest[15].(**string)) = nil
				*(dest[16].(*bool)) = true
				*(dest[17].(**time.Time)) = &approvedAt
				*(dest[18].(*time.Time)) = createdAt
				*(dest[19].(*time.Time)) = createdAt
				*(dest[20].(**time.Time)) = nil
				return nil
			},
		},
	}
	repo := pgrepo.NewRegistrationStore(q, "tenant-1")
	reg, err := repo.Get(id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if reg.ID != id {
		t.Errorf("ID = %q; want %q", reg.ID, id)
	}
	if reg.State != partner.RegistrationApproved {
		t.Errorf("State = %q; want approved", reg.State)
	}
	if reg.AGID != "agid:test:01" {
		t.Errorf("AGID = %q", reg.AGID)
	}
	if !reg.DNSVerified {
		t.Errorf("DNSVerified must round-trip true")
	}
}

func TestContractStore_Get_ScansRowIntoAggregate(t *testing.T) {
	t.Parallel()
	id := "01970000-0000-7000-c000-000000000c01"
	createdAt := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	caps := []byte(`[{"name":"recommend_content","tier":"medium","rate_limit_per_min":600}]`)
	q := &stubQuerier{
		rowScanners: []func(dest ...any) error{
			func(dest ...any) error {
				*(dest[0].(*string)) = id
				*(dest[1].(*string)) = "01970000-0000-7000-c000-000000000p01"
				*(dest[2].(*string)) = "api_key"
				*(dest[3].(*[]byte)) = caps
				*(dest[4].(*int)) = 1
				*(dest[5].(**string)) = nil
				*(dest[6].(**time.Time)) = nil
				*(dest[7].(*time.Time)) = createdAt
				*(dest[8].(*time.Time)) = createdAt
				*(dest[9].(**time.Time)) = nil
				return nil
			},
		},
	}
	repo := pgrepo.NewContractStore(q, "tenant-1")
	c, err := repo.Get(id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if c.AuthMethod != contract.AuthAPIKey {
		t.Errorf("AuthMethod = %q; want api_key", c.AuthMethod)
	}
	if len(c.Capabilities) != 1 || c.Capabilities[0].Name != "recommend_content" {
		t.Errorf("Capabilities = %v", c.Capabilities)
	}
	if c.Version != 1 {
		t.Errorf("Version = %d; want 1", c.Version)
	}
}

func TestInvocationStore_Get_ScansRowIntoAggregate(t *testing.T) {
	t.Parallel()
	id := "01970000-0000-7000-e000-000000000a01"
	startedAt := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	endedAt := startedAt.Add(123 * time.Millisecond)
	q := &stubQuerier{
		rowScanners: []func(dest ...any) error{
			func(dest ...any) error {
				*(dest[0].(*string)) = id
				*(dest[1].(*string)) = "agid:partner:cap:01"
				*(dest[2].(*string)) = "01970000-0000-7000-c000-000000000p01"
				*(dest[3].(*string)) = "recommend_content"
				*(dest[4].(*string)) = "corr-001"
				*(dest[5].(*string)) = "completed"
				*(dest[6].(*int)) = 123
				*(dest[7].(*int)) = 1024
				*(dest[8].(*string)) = ""
				*(dest[9].(*time.Time)) = startedAt
				*(dest[10].(**time.Time)) = &endedAt
				*(dest[11].(*string)) = ""
				*(dest[12].(*string)) = "https://a2a.chora.site/a2a/invoke#recommend_content"
				return nil
			},
		},
	}
	repo := pgrepo.NewInvocationStore(q, "tenant-1")
	inv, err := repo.Get(id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if inv.Status != invocation.StatusCompleted {
		t.Errorf("Status = %q", inv.Status)
	}
	if inv.LatencyMS != 123 {
		t.Errorf("LatencyMS = %d", inv.LatencyMS)
	}
	if inv.Endpoint != "https://a2a.chora.site/a2a/invoke#recommend_content" {
		t.Errorf("Endpoint = %q", inv.Endpoint)
	}
}

// Append duplicate id → ErrAlreadyExists via the isUniqueViolation probe.
func TestInvocationStore_Append_DuplicateReturnsErrAlreadyExists(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{
		execErr: errors.New(`pq: duplicate key value violates unique constraint "a2a_invocations_pkey"`),
	}
	repo := pgrepo.NewInvocationStore(q, "tenant-1")
	i, _ := invocation.New(invocation.NewParams{
		ID:            "01970000-0000-7000-e000-000000000dup",
		AGID:          "agid:p:c:01",
		PartnerID:     "01970000-0000-7000-c000-000000000p01",
		Capability:    "x",
		CorrelationID: "corr-dup",
	})
	if err := repo.Append(i); !errors.Is(err, pgrepo.ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists on PK collision; got %v", err)
	}
}

// nil aggregate → loud error.
func TestRegistrationStore_Put_NilRejected(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{}
	repo := pgrepo.NewRegistrationStore(q, "tenant-1")
	if err := repo.Put(nil); err == nil {
		t.Fatal("expected error for nil registration; got nil")
	}
}

func TestContractStore_Put_NilRejected(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{}
	repo := pgrepo.NewContractStore(q, "tenant-1")
	if err := repo.Put(nil); err == nil {
		t.Fatal("expected error for nil contract; got nil")
	}
}

func TestInvocationStore_Append_NilRejected(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{}
	repo := pgrepo.NewInvocationStore(q, "tenant-1")
	if err := repo.Append(nil); err == nil {
		t.Fatal("expected error for nil invocation; got nil")
	}
}
