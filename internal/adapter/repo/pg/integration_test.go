//go:build integration

// Package pg_test — real-Postgres integration tests for the pgx-backed
// RegistrationStore.
//
// These tests run ONLY under the `integration` build tag and skip cleanly
// when CHORA_TEST_DSN is unset. They exist because stub-querier tests cannot
// catch an omitted INSERT column — a silently dropped field survives a whole
// unit suite. Here we write a record with EVERY field distinct, read it
// back, and compare EVERY field.
package pg_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	chorapg "github.com/apollo-chora/chora-a2a-gateway/internal/adapter/pg"
	pgrepo "github.com/apollo-chora/chora-a2a-gateway/internal/adapter/repo/pg"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/partner"
)

// testDSN returns the integration DSN from the environment.
func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("CHORA_TEST_DSN")
	if dsn == "" {
		t.Skip("CHORA_TEST_DSN unset — skipping real-Postgres integration test")
	}
	return dsn
}

// newIntegrationQuerier connects to the real Postgres and returns a
// PgxPoolQuerier + cleanup.
func newIntegrationQuerier(t *testing.T) (*chorapg.PgxPoolQuerier, func()) {
	t.Helper()
	dsn := testDSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Fatalf("ping: %v", err)
	}
	return chorapg.NewPgxPoolQuerier(pool), func() { pool.Close() }
}

// TestRegistrationStore_IntegrationPutGetRoundTrip writes a registration with
// EVERY field set to a distinct value, reads it back, and compares EVERY
// field. This is the gate that catches an omitted INSERT column or a
// mis-ordered SELECT scan.
func TestRegistrationStore_IntegrationPutGetRoundTrip(t *testing.T) {
	q, cleanup := newIntegrationQuerier(t)
	defer cleanup()

	tenantID := "11111111-1111-7111-8111-111111111111"
	repo := pgrepo.NewRegistrationStore(q, tenantID)

	// Build a registration with every field distinct.
	reg, err := partner.NewRegistration(partner.RegistrationParams{
		ID:                 "01970000-0000-7000-a000-0000000000ff",
		OrgName:            "RoundTrip Org",
		ContactEmail:       "roundtrip@example.com",
		Capabilities:       []string{"cap_alpha", "cap_beta"},
		RequestedRateLimit: 4242,
	})
	if err != nil {
		t.Fatalf("NewRegistration: %v", err)
	}

	// Approve to populate the approval-side fields.
	apd := time.Date(2026, 3, 2, 1, 2, 3, 0, time.UTC)
	reg.State = partner.RegistrationApproved
	reg.Tier = partner.TierHigh
	reg.AGID = "agid:roundtrip:cap_alpha:01"
	reg.APIKeyHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	reg.ApprovedByGCID = "01970000-0000-7000-9000-0000000000aa"
	reg.ApprovedAt = &apd

	// Suspension-audit fields (distinct values; the DB stores whatever the
	// struct carries — the domain state machine is not the DB's concern).
	sud := time.Date(2026, 4, 3, 2, 3, 4, 0, time.UTC)
	reg.SuspendedByGCID = "01970000-0000-7000-9000-0000000000bb"
	reg.SuspendedAt = &sud
	reg.SuspendReason = "roundtrip_suspend_reason"

	// DNS verification fields.
	reg.PartnerDomain = "roundtrip.example.com"
	reg.DNSVerifyToken = "dns_token_roundtrip"
	reg.DNSVerified = true
	dvd := time.Date(2026, 5, 4, 3, 4, 5, 0, time.UTC)
	reg.DNSVerifiedAt = &dvd

	// Timestamps.
	reg.CreatedAt = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	reg.UpdatedAt = time.Date(2026, 2, 2, 0, 0, 0, 0, time.UTC)
	reg.DeletedAt = nil

	if err := repo.Put(reg); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Read it back.
	got, err := repo.Get(reg.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	// Compare EVERY field.
	if got.ID != reg.ID {
		t.Errorf("ID = %q; want %q", got.ID, reg.ID)
	}
	if got.OrgName != reg.OrgName {
		t.Errorf("OrgName = %q; want %q", got.OrgName, reg.OrgName)
	}
	if got.ContactEmail != reg.ContactEmail {
		t.Errorf("ContactEmail = %q; want %q", got.ContactEmail, reg.ContactEmail)
	}
	if len(got.Capabilities) != len(reg.Capabilities) {
		t.Fatalf("Capabilities len = %d; want %d", len(got.Capabilities), len(reg.Capabilities))
	}
	for i := range reg.Capabilities {
		if got.Capabilities[i] != reg.Capabilities[i] {
			t.Errorf("Capabilities[%d] = %q; want %q", i, got.Capabilities[i], reg.Capabilities[i])
		}
	}
	if got.RequestedRateLimit != reg.RequestedRateLimit {
		t.Errorf("RequestedRateLimit = %d; want %d", got.RequestedRateLimit, reg.RequestedRateLimit)
	}
	if got.State != reg.State {
		t.Errorf("State = %q; want %q", got.State, reg.State)
	}
	if got.Tier != reg.Tier {
		t.Errorf("Tier = %q; want %q", got.Tier, reg.Tier)
	}
	if got.AGID != reg.AGID {
		t.Errorf("AGID = %q; want %q", got.AGID, reg.AGID)
	}
	if got.APIKeyHash != reg.APIKeyHash {
		t.Errorf("APIKeyHash = %q; want %q", got.APIKeyHash, reg.APIKeyHash)
	}
	if got.ApprovedByGCID != reg.ApprovedByGCID {
		t.Errorf("ApprovedByGCID = %q; want %q", got.ApprovedByGCID, reg.ApprovedByGCID)
	}
	if got.ApprovedAt == nil || !got.ApprovedAt.Equal(*reg.ApprovedAt) {
		t.Errorf("ApprovedAt = %v; want %v", got.ApprovedAt, reg.ApprovedAt)
	}
	if got.SuspendedByGCID != reg.SuspendedByGCID {
		t.Errorf("SuspendedByGCID = %q; want %q", got.SuspendedByGCID, reg.SuspendedByGCID)
	}
	if got.SuspendedAt == nil || !got.SuspendedAt.Equal(*reg.SuspendedAt) {
		t.Errorf("SuspendedAt = %v; want %v", got.SuspendedAt, reg.SuspendedAt)
	}
	if got.SuspendReason != reg.SuspendReason {
		t.Errorf("SuspendReason = %q; want %q", got.SuspendReason, reg.SuspendReason)
	}
	if got.PartnerDomain != reg.PartnerDomain {
		t.Errorf("PartnerDomain = %q; want %q", got.PartnerDomain, reg.PartnerDomain)
	}
	if got.DNSVerifyToken != reg.DNSVerifyToken {
		t.Errorf("DNSVerifyToken = %q; want %q", got.DNSVerifyToken, reg.DNSVerifyToken)
	}
	if got.DNSVerified != reg.DNSVerified {
		t.Errorf("DNSVerified = %v; want %v", got.DNSVerified, reg.DNSVerified)
	}
	if got.DNSVerifiedAt == nil || !got.DNSVerifiedAt.Equal(*reg.DNSVerifiedAt) {
		t.Errorf("DNSVerifiedAt = %v; want %v", got.DNSVerifiedAt, reg.DNSVerifiedAt)
	}
	// created_at has no overwrite trigger — the provided value round-trips.
	if !got.CreatedAt.Equal(reg.CreatedAt) {
		t.Errorf("CreatedAt = %v; want %v", got.CreatedAt, reg.CreatedAt)
	}
	// updated_at is managed by the trg_partner_registrations_updated_at
	// trigger (NEW.updated_at = now() on INSERT), so the provided value is
	// intentionally overwritten. Assert it landed near now instead.
	if got.UpdatedAt.Before(time.Now().Add(-1*time.Minute)) || got.UpdatedAt.After(time.Now().Add(1*time.Minute)) {
		t.Errorf("UpdatedAt = %v; want ~now (trigger-managed)", got.UpdatedAt)
	}
	if got.DeletedAt != nil {
		t.Errorf("DeletedAt = %v; want nil", got.DeletedAt)
	}
}

// TestRegistrationStore_IntegrationGetByAGID verifies the AGID reverse lookup
// round-trips against real Postgres.
func TestRegistrationStore_IntegrationGetByAGID(t *testing.T) {
	q, cleanup := newIntegrationQuerier(t)
	defer cleanup()

	tenantID := "22222222-2222-7222-8222-222222222222"
	repo := pgrepo.NewRegistrationStore(q, tenantID)

	reg, err := partner.NewRegistration(partner.RegistrationParams{
		ID:                 "01970000-0000-7000-a000-0000000000ee",
		OrgName:            "AGID Org",
		ContactEmail:       "agid@example.com",
		Capabilities:       []string{"cap_gamma"},
		RequestedRateLimit: 777,
	})
	if err != nil {
		t.Fatalf("NewRegistration: %v", err)
	}
	reg.State = partner.RegistrationApproved
	reg.AGID = "agid:integration:cap_gamma:01"
	reg.Tier = partner.TierMedium

	if err := repo.Put(reg); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, err := repo.GetByAGID(reg.AGID)
	if err != nil {
		t.Fatalf("GetByAGID: %v", err)
	}
	if got.ID != reg.ID {
		t.Errorf("ID = %q; want %q", got.ID, reg.ID)
	}
	if got.AGID != reg.AGID {
		t.Errorf("AGID = %q; want %q", got.AGID, reg.AGID)
	}
	if got.OrgName != reg.OrgName {
		t.Errorf("OrgName = %q; want %q", got.OrgName, reg.OrgName)
	}
}
