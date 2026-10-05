// Package partner — TrustLevelView derivation for the O+ A2A Console.
//
// CRITICAL background — the chora-a2a domain already carries TWO distinct
// trust-related concepts:
//
//  1. `Tier` (registration_state.go) — drives default rate limits at
//     approval time (TierLow / TierMedium / TierHigh / TierCritical).
//  2. `chora.a2a.v1.TrustLevel` proto enum (UNTRUSTED / BASIC / VERIFIED /
//     PARTNER) — emitted on the external_agent.registered event for
//     cross-domain consumers.
//
// Neither maps directly to the FE-canonical A2A Console pill which is a
// three-bucket UI signal: `verified` / `pilot` / `experimental`. This file
// owns the derivation rule from the live registration aggregate state +
// the most recent invocation outcomes, which is the runtime-truth trust
// signal the O+ A2A Console renders.
//
// PER CLAUDE.md §11 [[feedback-no-stubs-real-wiring]]: no fake defaults.
// Every code path returns a value that reflects real backend signals; the
// caller never has to "fix up" an empty string. Suspended / deleted
// registrations are filtered upstream (only non-deleted, approved
// registrations should be listed on the O+ A2A Console — see
// inmem.RegistrationRepo.ListAll filtering), but the rule still handles
// pre-approval states honestly.
package partner

import (
	"time"

	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/invocation"
)

// TrustLevelView is the FE-canonical A2A trust pill string. Constants
// match chora-web governance.service.ts A2aExternalAgent.trust_level.
type TrustLevelView string

const (
	// TrustLevelExperimental — newest / least vetted bucket. Used for
	// registrations that have NOT verified their DNS-TXT challenge yet
	// (sandbox / early-stage partners). Pre-approval registrations also
	// fall here because no production-grade vetting has happened.
	TrustLevelExperimental TrustLevelView = "experimental"

	// TrustLevelPilot — production but unseasoned. Approved partner under
	// active monitoring. Default for any registration that does not meet
	// the `verified` bar — either because it is fresh (< 30 days since
	// approval), suspended, or has a degraded error-rate signal.
	TrustLevelPilot TrustLevelView = "pilot"

	// TrustLevelVerified — mature, vetted partner. ALL of the following
	// must hold to qualify:
	//   - State == approved
	//   - DNSVerified == true (DNS-TXT challenge cleared per ADR-132 §8)
	//   - ApprovedAt >= 30 days ago
	//   - In the last min(100, total) terminal invocations, error rate < 5%
	TrustLevelVerified TrustLevelView = "verified"
)

// trustVerifiedMinAgeDays is the minimum number of days an approved
// registration must have existed before it is eligible for `verified`.
const trustVerifiedMinAgeDays = 30

// trustVerifiedErrorRateWindow is the number of most-recent terminal
// invocations evaluated for the error-rate gate. Smaller windows are
// fine — when fewer invocations exist, the gate evaluates the available
// sample (with a minimum-sample threshold below to avoid false-failing
// brand-new partners).
const trustVerifiedErrorRateWindow = 100

// trustVerifiedMinSampleForErrorGate is the minimum number of terminal
// invocations required before the error-rate gate has any effect. Below
// this threshold the gate is skipped (treated as PASS) so a partner with
// 0-9 invocations is not punished for a single failure.
const trustVerifiedMinSampleForErrorGate = 10

// trustVerifiedMaxErrorRate is the maximum fraction of failed / scope-
// denied / rate-limited terminal invocations a partner can have in the
// scoring window and still qualify for `verified`. 0.05 == 5%.
const trustVerifiedMaxErrorRate = 0.05

// DeriveTrustLevelView returns the FE-canonical A2A Console trust pill
// (`verified` / `pilot` / `experimental`) for this registration, derived
// from real backend signals.
//
// ## Derivation rule (load-bearing — duplicated in oplus_router.go doc)
//
//   - State != approved              → experimental
//     (pending: not yet vetted; suspended: trust withdrawn until reinstated;
//     no production-grade trust standing while not actively approved)
//
//   - State == approved + NOT DNS-verified → experimental
//     (sandbox / early-stage partner — DNS-TXT challenge per ADR-132 §8
//     is the minimum gate that separates verified from sandbox)
//
//   - State == approved + DNS-verified + ApprovedAt < 30 days ago → pilot
//     (newly-onboarded; needs the 30-day monitoring window before promotion)
//
//   - State == approved + DNS-verified + ApprovedAt >= 30 days ago +
//     terminal-sample < 10 → verified
//     (matured, DNS-verified, no error signal because too few invocations
//     to evaluate — defaults to PASS on the error gate)
//
//   - State == approved + DNS-verified + ApprovedAt >= 30 days ago +
//     terminal-sample >= 10 + error-rate < 5% → verified
//
//   - State == approved + DNS-verified + ApprovedAt >= 30 days ago +
//     terminal-sample >= 10 + error-rate >= 5% → pilot
//     (degraded — was previously verified, error spike means stepped-down
//     to pilot for observation)
//
// `now` is dependency-injected for deterministic testing.
//
// `invocations` MUST be the list of this partner's invocations (i.e. those
// whose PartnerID == reg.ID). Caller fetches via InvocationRepo.ListByPartner;
// the method does NOT filter to the partner — it sums what it is given.
// nil / empty slice is legal (newly-approved partner with no traffic yet —
// passes the error gate by default).
func (r *Registration) DeriveTrustLevelView(now time.Time, invocations []*invocation.Invocation) TrustLevelView {
	// Gate 1 — must be approved.
	if r.State != RegistrationApproved {
		return TrustLevelExperimental
	}
	// Gate 2 — must be DNS-verified (ADR-132 §8 minimum trust gate).
	if !r.DNSVerified {
		return TrustLevelExperimental
	}
	// Gate 3 — must be ≥ 30 days since approval.
	if r.ApprovedAt == nil {
		// Defensive — an approved registration without ApprovedAt is a
		// data anomaly. Treat as not-mature.
		return TrustLevelPilot
	}
	age := now.Sub(*r.ApprovedAt)
	if age < trustVerifiedMinAgeDays*24*time.Hour {
		return TrustLevelPilot
	}
	// Gate 4 — error rate over the recent window must be < 5%.
	// Window is the most recent N terminal invocations (newest-first).
	terminalCount, errorCount := summariseTerminalWindow(invocations, trustVerifiedErrorRateWindow)
	if terminalCount < trustVerifiedMinSampleForErrorGate {
		// Insufficient signal — passes by default (matured, DNS-verified,
		// not enough traffic to fail the error gate).
		return TrustLevelVerified
	}
	errorRate := float64(errorCount) / float64(terminalCount)
	if errorRate >= trustVerifiedMaxErrorRate {
		// Degraded — step down to pilot for observation. A subsequent
		// derivation when error rate recovers will promote back.
		return TrustLevelPilot
	}
	return TrustLevelVerified
}

// summariseTerminalWindow walks invocations newest-first and returns
// (terminalCount, errorCount) over the most recent `windowSize` terminal
// (non-started) entries.
//
// Inputs are assumed to be in arbitrary order — the function sorts a
// shallow copy by StartedAt descending. Callers wanting strict ordering
// should sort upstream; this defensive copy keeps the domain method pure.
//
// Error classification: failed | rate_limited | scope_denied count as
// errors; completed is the only non-error terminal status. Started
// (in-flight) invocations are skipped — they are not yet a signal.
func summariseTerminalWindow(invocations []*invocation.Invocation, windowSize int) (terminal, errs int) {
	if len(invocations) == 0 || windowSize <= 0 {
		return 0, 0
	}
	// Shallow sort newest-first. Sort small inserts inline to avoid an
	// unconditional import of sort for this hot path; the slice is
	// expected to be small (≤ a few hundred entries per partner).
	sorted := make([]*invocation.Invocation, len(invocations))
	copy(sorted, invocations)
	// Insertion sort newest-first — O(n^2) worst case but the practical
	// upper bound is in the low hundreds. M14 swaps the in-memory list
	// for a `LIMIT 100 ORDER BY started_at DESC` SQL query.
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && sorted[j].StartedAt.After(sorted[j-1].StartedAt); j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}
	for _, inv := range sorted {
		if terminal >= windowSize {
			break
		}
		switch inv.Status {
		case invocation.StatusStarted:
			continue
		case invocation.StatusCompleted:
			terminal++
		case invocation.StatusFailed,
			invocation.StatusRateLimited,
			invocation.StatusScopeDenied:
			terminal++
			errs++
		}
	}
	return terminal, errs
}
