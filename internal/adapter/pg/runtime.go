// Package pg is the pgx-backed adapter for chora-a2a-gateway repository
// ports. Owns ONLY chora_a2a — cross-DB queries forbidden per
// ddd-enforcement.
//
// Architecture mirrors chora-identity / chora-notifications /
// chora-observability:
//
//   - Domain ports (PartnerStore semantics + invocation/contract repos)
//     are defined in internal/domain.
//   - This package implements the persistence side of those ports against
//     a *pgxpool.Pool.
//   - A small `Querier` interface decouples SQL from pgx so unit tests
//     stub the SQL surface without a live DB.
//
// Resilience-priority directive (`feedback_resilience_priority`):
//
//   - All tenant-scoped queries run inside a transaction with `SET LOCAL
//     chora.tenant_id` applied BEFORE the user query.
//   - Soft delete: queries default to `WHERE deleted_at IS NULL`.
//   - Append-only invocations: the migration installs a trigger that
//     forbids DELETE + most UPDATE columns; this repo only exposes
//     Append + GetByCorrelationID.
//
// AGID ≠ GCID is enforced at the domain layer (partner.Partner has NO
// Gcid field). This file's column lists therefore have no gcid columns
// for partner-scoped tables — defence-in-depth against accidental
// cross-domain leak.
package pg

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Querier is the minimal Exec + Query + QueryRow surface we need from pgx.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) error
	QueryRow(ctx context.Context, sql string, args ...any) Row
	Query(ctx context.Context, sql string, args ...any) (Rows, error)
}

type Row interface {
	Scan(dest ...any) error
}

type Rows interface {
	Next() bool
	Scan(dest ...any) error
	Close()
	Err() error
}

// ErrNoRows is the package-local sentinel.
var ErrNoRows = errors.New("pg: no rows in result set")

// PgxPoolQuerier wraps a *pgxpool.Pool with the local Querier shape.
type PgxPoolQuerier struct {
	pool *pgxpool.Pool
}

func NewPgxPoolQuerier(pool *pgxpool.Pool) *PgxPoolQuerier {
	return &PgxPoolQuerier{pool: pool}
}

func (q *PgxPoolQuerier) Exec(ctx context.Context, sql string, args ...any) error {
	if _, err := q.pool.Exec(ctx, sql, args...); err != nil {
		return fmt.Errorf("pg.Exec: %w", err)
	}
	return nil
}

func (q *PgxPoolQuerier) QueryRow(ctx context.Context, sql string, args ...any) Row {
	return &pgxPoolRow{r: q.pool.QueryRow(ctx, sql, args...)}
}

func (q *PgxPoolQuerier) Query(ctx context.Context, sql string, args ...any) (Rows, error) {
	rows, err := q.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("pg.Query: %w", err)
	}
	return &pgxPoolRows{r: rows}, nil
}

func (q *PgxPoolQuerier) Pool() *pgxpool.Pool { return q.pool }

type pgxPoolRow struct{ r pgx.Row }

func (r *pgxPoolRow) Scan(dest ...any) error {
	err := r.r.Scan(dest...)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNoRows
	}
	return err
}

type pgxPoolRows struct{ r pgx.Rows }

func (r *pgxPoolRows) Next() bool             { return r.r.Next() }
func (r *pgxPoolRows) Scan(dest ...any) error { return r.r.Scan(dest...) }
func (r *pgxPoolRows) Close()                 { r.r.Close() }
func (r *pgxPoolRows) Err() error             { return r.r.Err() }
