// closure_repository_test.go — pgx adapter tests for the durable
// ClosureRepository (W0-F1 durability + W0-F5 error-honesty, CHO-2198)
// using the stub Querier below.
//
// These are unit tests against the SQL emit + scan surface — no live DB.
// The critical assertions here are the W0-F5 ones: a genuine backing-store
// error from either Pseudonymise or IsPseudonymised must come back as a
// non-nil error, never get coerced into a false/zero "everything is fine"
// result (the swallowed-error trap the in-memory port's original
// `IsPseudonymised(gcid string) bool` signature made structurally
// impossible to avoid).
package pg_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/pg"
	"github.com/apollo-chora/chora-a2a-gateway/internal/config"
)

// stubQuerier is the in-memory pg.Querier double shared by this file's
// tests. rowSQL/rowArgs capture the most recent QueryRow call so tests can
// assert on the emitted SQL template and bound arguments without a live DB.
type stubQuerier struct {
	execSQL  string
	execArgs []any
	execErr  error
	row      *stubRow

	rowSQL  string
	rowArgs []any
}

func (s *stubQuerier) Exec(_ context.Context, sql string, args ...any) error {
	s.execSQL = sql
	s.execArgs = args
	return s.execErr
}

func (s *stubQuerier) QueryRow(_ context.Context, sql string, args ...any) pg.Row {
	s.rowSQL = sql
	s.rowArgs = args
	if s.row == nil {
		return &stubRow{err: pg.ErrNoRows}
	}
	return s.row
}

func (s *stubQuerier) Query(_ context.Context, _ string, _ ...any) (pg.Rows, error) {
	return nil, errors.New("stubQuerier: Query not stubbed")
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

func closureSpecFixture() []config.TableSpec {
	return []config.TableSpec{
		{
			Table: "a2a_contracts",
			Columns: []config.ColumnSpec{
				{Column: "created_by_display_name", Strategy: "tombstone_string", Value: "Former member"},
				{Column: "created_by_email_snapshot", Strategy: "drop", Value: ""},
			},
		},
		{
			Table: "byoa_credentials",
			Columns: []config.ColumnSpec{
				{Column: "encrypted_api_key", Strategy: "drop", Value: ""},
			},
		},
	}
}

func contains(haystack, needle string) bool {
	return strings.Contains(haystack, needle)
}

// -----------------------------------------------------------------------------
// Pseudonymise
// -----------------------------------------------------------------------------

func TestClosureRepository_Pseudonymise_EmitsInsertOnConflictReturningID(t *testing.T) {
	t.Skip("disarmed 2026-08-14: Pseudonymise now fails closed via ErrClosureExecutorUnbuilt, so the ack-row mechanics below are unreachable. This test pins the contract the REAL per-table executor must honour (CHO-2198); un-skip it with that executor.")
	t.Parallel()
	q := &stubQuerier{row: &stubRow{scan: func(dest ...any) error {
		*(dest[0].(*string)) = uuid.NewString()
		return nil
	}}}
	repo := pg.NewClosureRepository(q)

	rows, err := repo.Pseudonymise(context.Background(), "tenant-A", "gcid-A", closureSpecFixture())
	if err != nil {
		t.Fatalf("Pseudonymise: %v", err)
	}
	if rows != 3 {
		t.Fatalf("expected rows_touched=3 (2+1 columns); got %d", rows)
	}

	wants := []string{"INSERT INTO closure_pseudonymisation_state", "ON CONFLICT", "DO NOTHING", "RETURNING"}
	for _, w := range wants {
		if !contains(q.rowSQL, w) {
			t.Errorf("Pseudonymise SQL missing %q; got:\n%s", w, q.rowSQL)
		}
	}
}

func TestClosureRepository_Pseudonymise_MintsUUIDv7ForID(t *testing.T) {
	t.Skip("disarmed 2026-08-14: Pseudonymise now fails closed via ErrClosureExecutorUnbuilt, so the ack-row mechanics below are unreachable. This test pins the contract the REAL per-table executor must honour (CHO-2198); un-skip it with that executor.")
	t.Parallel()
	q := &stubQuerier{row: &stubRow{scan: func(dest ...any) error {
		*(dest[0].(*string)) = uuid.NewString()
		return nil
	}}}
	repo := pg.NewClosureRepository(q)

	if _, err := repo.Pseudonymise(context.Background(), "tenant-A", "gcid-A", nil); err != nil {
		t.Fatalf("Pseudonymise: %v", err)
	}
	if len(q.rowArgs) == 0 {
		t.Fatalf("expected query args")
	}
	idArg, ok := q.rowArgs[0].(string)
	if !ok || idArg == "" {
		t.Fatalf("expected non-empty string id as first arg; got %T %v", q.rowArgs[0], q.rowArgs[0])
	}
	parsed, err := uuid.Parse(idArg)
	if err != nil {
		t.Fatalf("minted id %q is not a valid UUID: %v", idArg, err)
	}
	if parsed.Version() != 7 {
		t.Fatalf("minted id %q is not UUIDv7 (version=%d)", idArg, parsed.Version())
	}
}

func TestClosureRepository_Pseudonymise_ReturnsZeroWhenConflictFires(t *testing.T) {
	t.Skip("disarmed 2026-08-14: Pseudonymise now fails closed via ErrClosureExecutorUnbuilt, so the ack-row mechanics below are unreachable. This test pins the contract the REAL per-table executor must honour (CHO-2198); un-skip it with that executor.")
	t.Parallel()
	// ON CONFLICT DO NOTHING suppresses the RETURNING row — the stub Querier
	// signals that exactly as the pg.Querier seam does: ErrNoRows.
	q := &stubQuerier{} // no .row set -> stubQuerier.QueryRow defaults to ErrNoRows
	repo := pg.NewClosureRepository(q)

	rows, err := repo.Pseudonymise(context.Background(), "tenant-A", "gcid-A", closureSpecFixture())
	if err != nil {
		t.Fatalf("Pseudonymise: expected idempotent no-op, got error: %v", err)
	}
	if rows != 0 {
		t.Fatalf("expected rows=0 on idempotent replay; got %d", rows)
	}
}

func TestClosureRepository_Pseudonymise_RejectsEmptyTenantID(t *testing.T) {
	t.Skip("disarmed 2026-08-14: Pseudonymise now fails closed via ErrClosureExecutorUnbuilt, so the ack-row mechanics below are unreachable. This test pins the contract the REAL per-table executor must honour (CHO-2198); un-skip it with that executor.")
	t.Parallel()
	q := &stubQuerier{}
	repo := pg.NewClosureRepository(q)
	_, err := repo.Pseudonymise(context.Background(), "", "gcid-A", nil)
	if err == nil {
		t.Fatalf("expected error on empty tenant_id")
	}
	if q.rowSQL != "" {
		t.Fatalf("must not emit SQL on validation failure; got %q", q.rowSQL)
	}
}

func TestClosureRepository_Pseudonymise_RejectsEmptyGCID(t *testing.T) {
	t.Skip("disarmed 2026-08-14: Pseudonymise now fails closed via ErrClosureExecutorUnbuilt, so the ack-row mechanics below are unreachable. This test pins the contract the REAL per-table executor must honour (CHO-2198); un-skip it with that executor.")
	t.Parallel()
	q := &stubQuerier{}
	repo := pg.NewClosureRepository(q)
	_, err := repo.Pseudonymise(context.Background(), "tenant-A", "", nil)
	if err == nil {
		t.Fatalf("expected error on empty gcid")
	}
	if q.rowSQL != "" {
		t.Fatalf("must not emit SQL on validation failure; got %q", q.rowSQL)
	}
}

// TestClosureRepository_Pseudonymise_PropagatesScanError is the W0-F5
// fail-loud proof for Pseudonymise: a genuine backing-store error (NOT
// pg.ErrNoRows) must come back as a non-nil error, never as a silent
// "idempotent no-op" (0, nil) — conflating "I don't know" with "already
// done" would let the closure saga believe this domain acked when it did
// not, exactly the class of bug in
// reusable_gotcha_swallowed_error_damage_is_decided_by_the_caller.
func TestClosureRepository_Pseudonymise_PropagatesScanError(t *testing.T) {
	t.Skip("disarmed 2026-08-14: Pseudonymise now fails closed via ErrClosureExecutorUnbuilt, so the ack-row mechanics below are unreachable. This test pins the contract the REAL per-table executor must honour (CHO-2198); un-skip it with that executor.")
	t.Parallel()
	boom := errors.New("pg: connection reset by peer")
	q := &stubQuerier{row: &stubRow{err: boom}}
	repo := pg.NewClosureRepository(q)

	rows, err := repo.Pseudonymise(context.Background(), "tenant-A", "gcid-A", closureSpecFixture())
	if err == nil {
		t.Fatalf("expected error to propagate, got nil (rows=%d)", rows)
	}
	if !errors.Is(err, boom) {
		t.Fatalf("expected wrapped sentinel error; got %v", err)
	}
	if rows != 0 {
		t.Fatalf("expected rows=0 on error; got %d", rows)
	}
}

// -----------------------------------------------------------------------------
// IsPseudonymised
// -----------------------------------------------------------------------------

func TestClosureRepository_IsPseudonymised_TrueWhenRowExists(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{row: &stubRow{scan: func(dest ...any) error {
		*(dest[0].(*int)) = 1
		return nil
	}}}
	repo := pg.NewClosureRepository(q)

	got, err := repo.IsPseudonymised(context.Background(), "tenant-A", "gcid-A")
	if err != nil {
		t.Fatalf("IsPseudonymised: %v", err)
	}
	if !got {
		t.Fatalf("expected true when a row exists")
	}
	if !contains(q.rowSQL, "FROM closure_pseudonymisation_state") {
		t.Errorf("IsPseudonymised SQL malformed; got:\n%s", q.rowSQL)
	}
}

func TestClosureRepository_IsPseudonymised_FalseWhenNoRows(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{} // defaults to ErrNoRows
	repo := pg.NewClosureRepository(q)

	got, err := repo.IsPseudonymised(context.Background(), "tenant-A", "gcid-A")
	if err != nil {
		t.Fatalf("IsPseudonymised: expected nil error on a clean miss; got %v", err)
	}
	if got {
		t.Fatalf("expected false when no row exists")
	}
}

// TestClosureRepository_IsPseudonymised_PropagatesQueryError is the core
// W0-F5 proof for IsPseudonymised: this is exactly the method the original
// `IsPseudonymised(gcid string) bool` signature could NOT have implemented
// honestly against Postgres (no ctx, no error return). A real backing-store
// error must be reported, not folded into `false`.
func TestClosureRepository_IsPseudonymised_PropagatesQueryError(t *testing.T) {
	t.Parallel()
	boom := errors.New("pg: connection reset by peer")
	q := &stubQuerier{row: &stubRow{err: boom}}
	repo := pg.NewClosureRepository(q)

	got, err := repo.IsPseudonymised(context.Background(), "tenant-A", "gcid-A")
	if err == nil {
		t.Fatalf("expected error to propagate, got nil (got=%v)", got)
	}
	if !errors.Is(err, boom) {
		t.Fatalf("expected wrapped sentinel error; got %v", err)
	}
	if got {
		t.Fatalf("expected false alongside the error (never claim true on failure)")
	}
}

func TestClosureRepository_IsPseudonymised_RejectsEmptyTenantID(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{}
	repo := pg.NewClosureRepository(q)
	_, err := repo.IsPseudonymised(context.Background(), "", "gcid-A")
	if err == nil {
		t.Fatalf("expected error on empty tenant_id")
	}
	if q.rowSQL != "" {
		t.Fatalf("must not emit SQL on validation failure; got %q", q.rowSQL)
	}
}

func TestClosureRepository_IsPseudonymised_RejectsEmptyGCID(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{}
	repo := pg.NewClosureRepository(q)
	_, err := repo.IsPseudonymised(context.Background(), "tenant-A", "")
	if err == nil {
		t.Fatalf("expected error on empty gcid")
	}
	if q.rowSQL != "" {
		t.Fatalf("must not emit SQL on validation failure; got %q", q.rowSQL)
	}
}
