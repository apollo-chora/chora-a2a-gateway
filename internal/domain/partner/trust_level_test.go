// Package partner_test — table-driven tests for the FE-canonical
// trust-level derivation rule (trust_level.go).
package partner_test

import (
	"testing"
	"time"

	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/invocation"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/partner"
)

// trustNow is the fixed reference clock all table-driven cases derive from.
var trustNow = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

// mkInv builds a terminal invocation with the given outcome, anchored at
// startedAt. Convenience helper for table cases.
func mkInv(t *testing.T, partnerID, agid string, startedAt time.Time, status invocation.Status) *invocation.Invocation {
	t.Helper()
	inv, err := invocation.New(invocation.NewParams{
		ID:            "01970000-0000-7000-d000-" + startedAt.Format("150405.000000")[:12],
		AGID:          agid,
		PartnerID:     partnerID,
		Capability:    "recommend_content",
		CorrelationID: startedAt.Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatalf("invocation.New: %v", err)
	}
	// Force startedAt for deterministic windowing.
	inv.StartedAt = startedAt
	switch status {
	case invocation.StatusCompleted:
		_ = inv.Complete(128)
	case invocation.StatusFailed:
		_ = inv.Fail("UPSTREAM_500")
	case invocation.StatusRateLimited:
		_ = inv.RateLimit()
	case invocation.StatusScopeDenied:
		_ = inv.ScopeDeny("missing read:atoms")
	case invocation.StatusStarted:
		// Leave as started — non-terminal, ignored by the window.
	}
	// EndedAt was set by terminate(); clamp to startedAt for determinism
	// (latency doesn't matter for trust derivation).
	if inv.EndedAt != nil {
		end := startedAt.Add(50 * time.Millisecond)
		inv.EndedAt = &end
	}
	return inv
}

// mkRegistration constructs a Registration in a target state for table
// cases. Defaults are approved + DNS-verified + 60 days old; flags below
// override individual gates.
func mkRegistration(t *testing.T, opts ...func(*partner.Registration)) *partner.Registration {
	t.Helper()
	r, err := partner.NewRegistration(partner.RegistrationParams{
		ID:                 "01970000-0000-7000-c000-000000000r99",
		OrgName:            "TableTest",
		ContactEmail:       "ops@table.example",
		Capabilities:       []string{"recommend_content"},
		RequestedRateLimit: 100,
	})
	if err != nil {
		t.Fatalf("NewRegistration: %v", err)
	}
	// Default to mature approved DNS-verified.
	if _, err := r.Approve(partner.ApprovalParams{
		ApprovedByGCID: "01970000-0000-7000-9000-0000000000aa",
		Tier:           partner.TierMedium,
	}); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	approvedAt := trustNow.Add(-60 * 24 * time.Hour)
	r.ApprovedAt = &approvedAt
	r.DNSVerified = true
	verifiedAt := approvedAt
	r.DNSVerifiedAt = &verifiedAt
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// withState forces the registration's state for table-driven cases.
func withState(state partner.RegistrationState) func(*partner.Registration) {
	return func(r *partner.Registration) { r.State = state }
}

// withDNSUnverified flips DNSVerified to false.
func withDNSUnverified() func(*partner.Registration) {
	return func(r *partner.Registration) {
		r.DNSVerified = false
		r.DNSVerifiedAt = nil
	}
}

// withApprovedDaysAgo overrides ApprovedAt to `days` ago from trustNow.
func withApprovedDaysAgo(days int) func(*partner.Registration) {
	return func(r *partner.Registration) {
		at := trustNow.Add(-time.Duration(days) * 24 * time.Hour)
		r.ApprovedAt = &at
	}
}

// withoutApprovedAt nulls ApprovedAt to exercise the defensive branch.
func withoutApprovedAt() func(*partner.Registration) {
	return func(r *partner.Registration) { r.ApprovedAt = nil }
}

func TestDeriveTrustLevelView_TableDriven(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		regOpts     []func(*partner.Registration)
		invocations func(t *testing.T, partnerID, agid string) []*invocation.Invocation
		want        partner.TrustLevelView
	}{
		{
			name:    "pending registration → experimental",
			regOpts: []func(*partner.Registration){withState(partner.RegistrationPending)},
			want:    partner.TrustLevelExperimental,
		},
		{
			name:    "suspended registration → experimental",
			regOpts: []func(*partner.Registration){withState(partner.RegistrationSuspended)},
			want:    partner.TrustLevelExperimental,
		},
		{
			name:    "approved but DNS not verified → experimental",
			regOpts: []func(*partner.Registration){withDNSUnverified()},
			want:    partner.TrustLevelExperimental,
		},
		{
			name:    "approved + DNS-verified + 10 days old → pilot (too new)",
			regOpts: []func(*partner.Registration){withApprovedDaysAgo(10)},
			want:    partner.TrustLevelPilot,
		},
		{
			name:    "approved + DNS-verified + exactly 30 days old → verified (boundary)",
			regOpts: []func(*partner.Registration){withApprovedDaysAgo(30)},
			want:    partner.TrustLevelVerified,
		},
		{
			name:    "approved + DNS-verified + 60 days old + no invocations → verified",
			regOpts: nil,
			want:    partner.TrustLevelVerified,
		},
		{
			name:    "approved + DNS-verified + 60 days old + 5 invocations all-failed → verified (sample below min)",
			regOpts: nil,
			invocations: func(t *testing.T, pid, agid string) []*invocation.Invocation {
				out := []*invocation.Invocation{}
				for i := 0; i < 5; i++ {
					out = append(out, mkInv(t, pid, agid,
						trustNow.Add(-time.Duration(i+1)*time.Hour),
						invocation.StatusFailed))
				}
				return out
			},
			want: partner.TrustLevelVerified,
		},
		{
			name:    "approved + DNS-verified + 60 days old + 20 invocations 19 complete 1 fail (5%) → pilot",
			regOpts: nil,
			invocations: func(t *testing.T, pid, agid string) []*invocation.Invocation {
				out := []*invocation.Invocation{}
				for i := 0; i < 19; i++ {
					out = append(out, mkInv(t, pid, agid,
						trustNow.Add(-time.Duration(i+1)*time.Hour),
						invocation.StatusCompleted))
				}
				out = append(out, mkInv(t, pid, agid,
					trustNow.Add(-time.Duration(20)*time.Hour),
					invocation.StatusFailed))
				return out
			},
			want: partner.TrustLevelPilot, // 1/20 = 5% — exceeds <5% strict bound.
		},
		{
			name:    "approved + DNS-verified + 60 days old + 20 invocations 19 complete 1 rate_limited → pilot",
			regOpts: nil,
			invocations: func(t *testing.T, pid, agid string) []*invocation.Invocation {
				out := []*invocation.Invocation{}
				for i := 0; i < 19; i++ {
					out = append(out, mkInv(t, pid, agid,
						trustNow.Add(-time.Duration(i+1)*time.Hour),
						invocation.StatusCompleted))
				}
				out = append(out, mkInv(t, pid, agid,
					trustNow.Add(-time.Duration(20)*time.Hour),
					invocation.StatusRateLimited))
				return out
			},
			want: partner.TrustLevelPilot,
		},
		{
			name:    "approved + DNS-verified + 60 days old + 100 invocations 4 failures (4%) → verified",
			regOpts: nil,
			invocations: func(t *testing.T, pid, agid string) []*invocation.Invocation {
				out := []*invocation.Invocation{}
				for i := 0; i < 96; i++ {
					out = append(out, mkInv(t, pid, agid,
						trustNow.Add(-time.Duration(i+1)*time.Hour),
						invocation.StatusCompleted))
				}
				for i := 96; i < 100; i++ {
					out = append(out, mkInv(t, pid, agid,
						trustNow.Add(-time.Duration(i+1)*time.Hour),
						invocation.StatusFailed))
				}
				return out
			},
			want: partner.TrustLevelVerified,
		},
		{
			name:    "approved + DNS-verified + 60 days old + 100 invocations 5 failures (5%) → pilot",
			regOpts: nil,
			invocations: func(t *testing.T, pid, agid string) []*invocation.Invocation {
				out := []*invocation.Invocation{}
				for i := 0; i < 95; i++ {
					out = append(out, mkInv(t, pid, agid,
						trustNow.Add(-time.Duration(i+1)*time.Hour),
						invocation.StatusCompleted))
				}
				for i := 95; i < 100; i++ {
					out = append(out, mkInv(t, pid, agid,
						trustNow.Add(-time.Duration(i+1)*time.Hour),
						invocation.StatusFailed))
				}
				return out
			},
			want: partner.TrustLevelPilot,
		},
		{
			name:    "approved + DNS-verified + 60 days old + started invocations only → verified (started skipped)",
			regOpts: nil,
			invocations: func(t *testing.T, pid, agid string) []*invocation.Invocation {
				out := []*invocation.Invocation{}
				for i := 0; i < 30; i++ {
					out = append(out, mkInv(t, pid, agid,
						trustNow.Add(-time.Duration(i+1)*time.Hour),
						invocation.StatusStarted))
				}
				return out
			},
			want: partner.TrustLevelVerified,
		},
		{
			name:    "approved + DNS-verified + 60 days old + window honored: 100 most-recent only",
			regOpts: nil,
			invocations: func(t *testing.T, pid, agid string) []*invocation.Invocation {
				// 100 most-recent: all completed → 0% errors.
				// 50 older: all failed (ancient mistakes).
				// Window of 100 should ignore the older 50 → verified.
				out := []*invocation.Invocation{}
				for i := 0; i < 100; i++ {
					out = append(out, mkInv(t, pid, agid,
						trustNow.Add(-time.Duration(i+1)*time.Hour),
						invocation.StatusCompleted))
				}
				for i := 100; i < 150; i++ {
					out = append(out, mkInv(t, pid, agid,
						trustNow.Add(-time.Duration(i+1)*time.Hour),
						invocation.StatusFailed))
				}
				return out
			},
			want: partner.TrustLevelVerified,
		},
		{
			name:    "approved + DNS-verified + ApprovedAt nil → pilot (defensive)",
			regOpts: []func(*partner.Registration){withoutApprovedAt()},
			want:    partner.TrustLevelPilot,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			reg := mkRegistration(t, tc.regOpts...)
			var invs []*invocation.Invocation
			if tc.invocations != nil {
				invs = tc.invocations(t, reg.ID, reg.AGID)
			}
			got := reg.DeriveTrustLevelView(trustNow, invs)
			if got != tc.want {
				t.Errorf("DeriveTrustLevelView = %q; want %q", got, tc.want)
			}
		})
	}
}

// TestDeriveTrustLevelView_NilInvocations exercises the nil-slice branch
// explicitly (vs the empty-slice case in the table).
func TestDeriveTrustLevelView_NilInvocations(t *testing.T) {
	t.Parallel()
	reg := mkRegistration(t)
	got := reg.DeriveTrustLevelView(trustNow, nil)
	if got != partner.TrustLevelVerified {
		t.Errorf("DeriveTrustLevelView(nil) = %q; want verified (mature partner, no traffic, gate skipped)", got)
	}
}

// TestDeriveTrustLevelView_DegradedRecoveryPath asserts a verified partner
// dropping to pilot on degraded error rate, then returning to verified
// after the error tail rolls out of the window — the documented
// "step-down, step-back-up" path.
func TestDeriveTrustLevelView_DegradedRecoveryPath(t *testing.T) {
	t.Parallel()
	reg := mkRegistration(t)

	// Phase 1 — 95 completed + 5 failed in window → 5% → pilot.
	invs := []*invocation.Invocation{}
	for i := 0; i < 95; i++ {
		invs = append(invs, mkInv(t, reg.ID, reg.AGID,
			trustNow.Add(-time.Duration(i+1)*time.Hour),
			invocation.StatusCompleted))
	}
	for i := 95; i < 100; i++ {
		invs = append(invs, mkInv(t, reg.ID, reg.AGID,
			trustNow.Add(-time.Duration(i+1)*time.Hour),
			invocation.StatusFailed))
	}
	if got := reg.DeriveTrustLevelView(trustNow, invs); got != partner.TrustLevelPilot {
		t.Fatalf("phase1 (5%% errors) → %q; want pilot", got)
	}

	// Phase 2 — add 96 fresh successful invocations (most-recent 100 are
	// now 96 successes + 4 of the original failures, hence 4%) → verified.
	for i := 0; i < 96; i++ {
		invs = append(invs, mkInv(t, reg.ID, reg.AGID,
			trustNow.Add(time.Duration(i+1)*time.Hour),
			invocation.StatusCompleted))
	}
	if got := reg.DeriveTrustLevelView(trustNow, invs); got != partner.TrustLevelVerified {
		t.Errorf("phase2 (recovered) → %q; want verified", got)
	}
}
