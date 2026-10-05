// partner_repository_test.go — pgx adapter tests using a stub Querier.
//
// AGID ≠ GCID invariant: the partner aggregate has no GCID field; the
// SQL emitted by this repo MUST NOT include a gcid column. This is
// enforced both by the domain (Partner struct) and by the table
// (no gcid column in partners — see migrations/0001_initial.sql).
//
// Credential-hash invariant (security): Put MUST persist the REAL
// api_key_hash carried on the aggregate (minted once at
// Registration.Approve), NEVER a placeholder derivable from the public
// AGID. A Partner reaching Put with an empty APIKeyHash is a programmer
// error and Put MUST fail loud rather than write a blank/forgeable hash.
package pg_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/pg"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/partner"
)

const approverGCID = "01970000-0000-7000-9000-0000000000aa"

type stubQuerier struct {
	execSQL  string
	execArgs []any
	execErr  error
	row      *stubRow

	// rowSQL/rowArgs capture the most recent QueryRow call so tests (e.g.
	// closure_repository_test.go) can assert on the emitted SQL template
	// and bound arguments without a live DB. Additive — partner_repository
	// tests never inspected these before and are unaffected.
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

// agidDerivedPlaceholder reproduces the DELETED derivePlaceholderAPIKeyHash
// helper so tests can assert the persisted hash is NOT this forgeable,
// public-AGID-derivable value.
func agidDerivedPlaceholder(agid string) string {
	h := strings.ReplaceAll(agid, "-", "")
	for len(h) < 64 {
		h += "0"
	}
	return h[:64]
}

// approvedPartner mints a REAL credential via Registration.Approve and
// returns an active Partner carrying the real api_key_hash plus the
// one-time plaintext for round-trip verification.
func approvedPartner(t *testing.T) (*partner.Partner, string) {
	t.Helper()
	reg, err := partner.NewRegistration(partner.RegistrationParams{
		ID:                 uuid.NewString(),
		OrgName:            "Atlas Skills NDI",
		ContactEmail:       "ops@atlas.example",
		Capabilities:       []string{"recommend_content"},
		RequestedRateLimit: 60,
	})
	if err != nil {
		t.Fatalf("NewRegistration: %v", err)
	}
	res, err := reg.Approve(partner.ApprovalParams{
		ApprovedByGCID: approverGCID,
		Tier:           partner.TierMedium,
	})
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	p, err := partner.New(partner.NewParams{
		AGID:            reg.AGID,
		Name:            reg.OrgName,
		AllowedScopes:   reg.Capabilities,
		RateLimitPerMin: 60,
		QuotaPerDay:     1000,
		APIKeyHash:      reg.APIKeyHash,
	})
	if err != nil {
		t.Fatalf("partner.New: %v", err)
	}
	return p, res.APIKeyPlaintext
}

func TestPartnerRepository_Put_EmitsUpsertSQL_NoGcidColumn(t *testing.T) {
	t.Parallel()
	p, _ := approvedPartner(t)

	q := &stubQuerier{}
	tenantID := uuid.NewString()
	repo := pg.NewPartnerRepository(q)

	if err := repo.Put(context.Background(), tenantID, p); err != nil {
		t.Fatalf("Put: %v", err)
	}

	if !strings.Contains(q.execSQL, "INSERT INTO partners") {
		t.Errorf("expected INSERT into partners; got:\n%s", q.execSQL)
	}
	// AGID ≠ GCID: SQL MUST NOT contain a gcid column reference.
	if strings.Contains(strings.ToLower(q.execSQL), "gcid") {
		t.Errorf("partner SQL must not reference gcid; AGID is the only identity. SQL:\n%s", q.execSQL)
	}
	// agid is the primary key; tenant_id second; api_key_hash fifth.
	if len(q.execArgs) < 5 {
		t.Fatalf("expected ≥ 5 args; got %d", len(q.execArgs))
	}
	if q.execArgs[0] != p.AGID {
		t.Errorf("arg[0] = %v; want AGID %q", q.execArgs[0], p.AGID)
	}
	if q.execArgs[1] != tenantID {
		t.Errorf("arg[1] = %v; want tenant %q", q.execArgs[1], tenantID)
	}
	if q.execArgs[4] != p.APIKeyHash {
		t.Errorf("arg[4] (api_key_hash) = %v; want real hash %q", q.execArgs[4], p.APIKeyHash)
	}
}

// TestPartnerRepository_Put_BindsRealHash_NotAGIDDerived is the load-bearing
// security assertion: the persisted hash is the SHA-256 of the one-time
// plaintext minted at approval — NEVER the public-AGID-derivable placeholder.
func TestPartnerRepository_Put_BindsRealHash_NotAGIDDerived(t *testing.T) {
	t.Parallel()
	p, plaintext := approvedPartner(t)

	q := &stubQuerier{}
	repo := pg.NewPartnerRepository(q)
	if err := repo.Put(context.Background(), uuid.NewString(), p); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, ok := q.execArgs[4].(string)
	if !ok {
		t.Fatalf("arg[4] not a string: %T", q.execArgs[4])
	}
	// MUST be the real SHA-256 of the one-time plaintext...
	sum := sha256.Sum256([]byte(plaintext))
	want := hex.EncodeToString(sum[:])
	if got != want {
		t.Errorf("persisted api_key_hash = %q; want real hash of plaintext %q", got, want)
	}
	// ...and MUST NOT be the forgeable public-AGID-derived placeholder.
	if got == agidDerivedPlaceholder(p.AGID) {
		t.Errorf("persisted api_key_hash is the AGID-derived placeholder %q — forgeable from the public AGID", got)
	}
}

// TestPartnerRepository_Put_EmptyAPIKeyHash_FailsLoud proves a Partner with
// no minted credential is NEVER silently persisted with a blank/placeholder
// hash — Put returns an error and emits no SQL.
func TestPartnerRepository_Put_EmptyAPIKeyHash_FailsLoud(t *testing.T) {
	t.Parallel()
	p, err := partner.New(partner.NewParams{
		AGID:            uuid.NewString(),
		Name:            "No-Key Partner",
		AllowedScopes:   []string{"recommend_content"},
		RateLimitPerMin: 60,
		QuotaPerDay:     1000,
		// APIKeyHash intentionally empty.
	})
	if err != nil {
		t.Fatalf("partner.New: %v", err)
	}
	q := &stubQuerier{}
	repo := pg.NewPartnerRepository(q)
	if err := repo.Put(context.Background(), uuid.NewString(), p); err == nil {
		t.Fatal("expected fail-loud error for empty APIKeyHash; got nil")
	}
	if q.execSQL != "" {
		t.Errorf("Put must NOT emit SQL when APIKeyHash is empty; emitted:\n%s", q.execSQL)
	}
}

func TestPartnerRepository_Get_ReturnsErrNotFound_OnMiss(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{} // QueryRow → stubRow{err: ErrNoRows}
	repo := pg.NewPartnerRepository(q)
	_, err := repo.Get(context.Background(), uuid.NewString(), uuid.NewString())
	if !errors.Is(err, pg.ErrPartnerNotFound) {
		t.Fatalf("expected ErrPartnerNotFound on miss; got %v", err)
	}
}

// TestPartnerRepository_Get_RehydratesAPIKeyHash proves the real hash is
// read back into the aggregate — the column is not write-only.
func TestPartnerRepository_Get_RehydratesAPIKeyHash(t *testing.T) {
	t.Parallel()
	agid := uuid.NewString()
	const realHash = "a1b2c3d4e5f600112233445566778899aabbccddeeff00112233445566778899"
	q := &stubQuerier{
		row: &stubRow{
			scan: func(dest ...any) error {
				*(dest[0].(*string)) = agid     // agid
				*(dest[2].(*string)) = realHash // api_key_hash
				*(dest[3].(*string)) = "active" // status
				return nil
			},
		},
	}
	repo := pg.NewPartnerRepository(q)
	p, err := repo.Get(context.Background(), uuid.NewString(), agid)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if p.APIKeyHash != realHash {
		t.Errorf("APIKeyHash = %q; want rehydrated %q", p.APIKeyHash, realHash)
	}
	if p.AGID != agid {
		t.Errorf("AGID = %q; want %q", p.AGID, agid)
	}
}

// TestPartnerRepository_Get_RehydratesNullableFields drives the non-nil
// branches of the scan (suspended_at / suspend_reason / deleted_at present),
// which the primitive rehydrate test leaves nil.
func TestPartnerRepository_Get_RehydratesNullableFields(t *testing.T) {
	t.Parallel()
	agid := uuid.NewString()
	suspendedAt := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	deletedAt := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	q := &stubQuerier{
		row: &stubRow{
			scan: func(dest ...any) error {
				*(dest[0].(*string)) = agid
				*(dest[1].(*string)) = "Acme"
				*(dest[2].(*string)) = "hash"
				*(dest[3].(*string)) = "suspended"
				sa := suspendedAt
				*(dest[4].(**time.Time)) = &sa
				reason := "compliance_review"
				*(dest[5].(**string)) = &reason
				*(dest[6].(*int)) = 100
				*(dest[7].(*int)) = 10000
				*(dest[8].(*[]string)) = []string{"recommend_content"}
				*(dest[9].(*time.Time)) = suspendedAt
				*(dest[10].(*time.Time)) = suspendedAt
				da := deletedAt
				*(dest[11].(**time.Time)) = &da
				return nil
			},
		},
	}
	repo := pg.NewPartnerRepository(q)
	p, err := repo.Get(context.Background(), uuid.NewString(), agid)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if p.Status != partner.StatusSuspended {
		t.Errorf("Status = %q; want suspended", p.Status)
	}
	if p.SuspendedAt == nil || !p.SuspendedAt.Equal(suspendedAt) {
		t.Errorf("SuspendedAt = %v; want %v", p.SuspendedAt, suspendedAt)
	}
	if p.SuspendReason != "compliance_review" {
		t.Errorf("SuspendReason = %q; want compliance_review", p.SuspendReason)
	}
	if p.DeletedAt == nil || !p.DeletedAt.Equal(deletedAt) {
		t.Errorf("DeletedAt = %v; want %v", p.DeletedAt, deletedAt)
	}
	if len(p.AllowedScopes) != 1 || p.AllowedScopes[0] != "recommend_content" {
		t.Errorf("AllowedScopes = %v", p.AllowedScopes)
	}
}

func TestPartnerRepository_Put_NilPartner_Rejected(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{}
	repo := pg.NewPartnerRepository(q)
	if err := repo.Put(context.Background(), uuid.NewString(), nil); err == nil {
		t.Fatal("expected error for nil partner; got nil")
	}
}

func TestPartnerRepository_Put_EmptyTenant_Rejected(t *testing.T) {
	t.Parallel()
	p, _ := approvedPartner(t)
	q := &stubQuerier{}
	repo := pg.NewPartnerRepository(q)
	if err := repo.Put(context.Background(), "   ", p); err == nil {
		t.Fatal("expected error for empty tenantID; got nil")
	}
	if q.execSQL != "" {
		t.Errorf("Put must NOT emit SQL when tenantID is empty; emitted:\n%s", q.execSQL)
	}
}
