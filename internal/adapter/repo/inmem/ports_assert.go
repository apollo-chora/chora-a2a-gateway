// ports_assert.go — compile-time checks that the in-memory implementations
// satisfy the matching port interfaces in
// internal/adapter/repo/ports.go.
package inmem

import "github.com/apollo-chora/chora-a2a-gateway/internal/adapter/repo"

var (
	_ repo.RegistrationStore = (*RegistrationRepo)(nil)
	_ repo.ContractStore     = (*ContractRepo)(nil)
	_ repo.InvocationStore   = (*InvocationRepo)(nil)
	_ repo.MCPConfigStore    = (*MCPConfigRepo)(nil)
	_ repo.BYOAKeyStore      = (*BYOAKeyRepo)(nil)
)
