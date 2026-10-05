// Package partner — AGID minter.
//
// Per CLAUDE.md §1 + ddd-enforcement #10: AGID is the Agent Global Identifier,
// distinct from GCID. Agents CANNOT hold TenantMembership.
//
// AGID format (task spec): `agid:{partner_id}:{capability}:{instance}`.
//
// MintAGID is deterministic: the same (partner_id, capability, instance)
// triple always produces the same AGID. This makes registration replays
// idempotent without external coordination.
package partner

import (
	"errors"
	"strings"
)

// AGIDPrefix is the canonical prefix for partner-derived AGIDs.
const AGIDPrefix = "agid:"

// MintAGID returns the canonical AGID string for a (partner_id, capability,
// instance) triple. The function is deterministic and idempotent.
//
// All three inputs are required and must be non-empty after trimming
// whitespace. The function performs no encoding or escaping — callers must
// supply already-canonicalised values (UUIDv7 partner ID, snake_case
// capability name, opaque instance index).
func MintAGID(partnerID, capability, instance string) (string, error) {
	if strings.TrimSpace(partnerID) == "" {
		return "", errors.New("partner: MintAGID partnerID required")
	}
	if strings.TrimSpace(capability) == "" {
		return "", errors.New("partner: MintAGID capability required")
	}
	if strings.TrimSpace(instance) == "" {
		return "", errors.New("partner: MintAGID instance required")
	}
	return AGIDPrefix + partnerID + ":" + capability + ":" + instance, nil
}
