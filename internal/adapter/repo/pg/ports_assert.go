// ports_assert.go — compile-time checks that the pg implementations
// satisfy the matching port interfaces in
// internal/adapter/repo/ports.go.
//
// Per the M12 backlog deliverable, both backends — inmem (legacy/default)
// and pg (production) — MUST satisfy the same port surface so the
// cmd/server/main.go env-driven backend selector can swap them at the
// adapter wiring layer.
package pg

import "github.com/apollo-chora/chora-a2a-gateway/internal/adapter/repo"

var (
	_ repo.RegistrationStore = (*RegistrationStore)(nil)
	_ repo.ContractStore     = (*ContractStore)(nil)
	_ repo.InvocationStore   = (*InvocationStore)(nil)
	_ repo.MCPConfigStore    = (*MCPConfigStore)(nil)
	_ repo.BYOAKeyStore      = (*BYOAKeyStore)(nil)
	_ repo.IdentityStore     = (*IdentityStore)(nil)
)
