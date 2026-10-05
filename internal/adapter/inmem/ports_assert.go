// ports_assert.go — compile-time check that the legacy in-memory
// IdentityStore satisfies the repo.IdentityStore port
// (internal/adapter/repo/ports.go).
//
// Per W0-F1 (CHO-2198) the ExternalAgentIdentity store is now selectable
// between this in-memory adapter (dev/default) and the pg adapter
// (internal/adapter/repo/pg/identity.go, durable) behind one port, so
// cmd/server/bootstrap.go's chooseIdentityBackend can swap them.
package inmem

import "github.com/apollo-chora/chora-a2a-gateway/internal/adapter/repo"

var _ repo.IdentityStore = (*IdentityStore)(nil)
