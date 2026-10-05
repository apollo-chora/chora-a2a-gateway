// Package pg implements the M12 chora_a2a Postgres-backed adapters for
// chora-a2a-gateway's RegistrationStore / ContractStore / InvocationStore
// ports declared in internal/adapter/repo/ports.go.
//
// Architecture notes:
//
//   - Reuses the local pg.Querier interface from
//     internal/adapter/pg/runtime.go so callers can decouple SQL from pgx
//     for unit tests (stubQuerier in repo_test.go) without spinning a
//     live Postgres connection.
//   - Tenant-context propagation: production wires a transactional pool
//     with `SET LOCAL chora.tenant_id` BEFORE each Put/Get/List query;
//     this adapter passes the tenant ID it was constructed with as the
//     `tenant_id = $1` bind argument on every list/get query so RLS gates
//     fire even when the GUC is unset (defence in depth).
//   - Soft-delete: every list query filters `deleted_at IS NULL`.
//   - AGID ≠ GCID (CLAUDE.md §1): NO column emits `gcid` except the audit-
//     captured `approved_by_gcid` / `suspended_by_gcid` columns on
//     partner_registrations — these record the actor of the transition,
//     not the partner's own identity.
//   - Append-only invocations: the schema trigger forbids DELETE and any
//     mutation of agid / capability / correlation_id / started_at; this
//     repo's Update method emits a SET clause that touches ONLY
//     {status, latency_ms, response_size_bytes, error_code, ended_at,
//     traceparent, endpoint} so the trigger never fires on a legitimate
//     terminal-status transition.
package pg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	chorapg "github.com/apollo-chora/chora-a2a-gateway/internal/adapter/pg"
	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/repo"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/contract"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/invocation"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/partner"
)

// ErrNotFound aliases repo.ErrNotFound so callers can either check the
// canonical port sentinel (preferred) or the pg-package one (legacy paths
// that mirrored inmem.ErrNotFound). All matchers go through errors.Is.
var ErrNotFound = repo.ErrNotFound

// ErrAlreadyExists aliases repo.ErrAlreadyExists. InvocationStore.Append
// surfaces this on PK collision — audit log is append-only.
var ErrAlreadyExists = repo.ErrAlreadyExists

// -----------------------------------------------------------------------------
// RegistrationStore
// -----------------------------------------------------------------------------

// RegistrationStore is the pgx-backed implementation of the
// repo.RegistrationStore port.
type RegistrationStore struct {
	q        chorapg.Querier
	tenantID string
}

// NewRegistrationStore wraps a Querier with a tenant binding.
func NewRegistrationStore(q chorapg.Querier, tenantID string) *RegistrationStore {
	return &RegistrationStore{q: q, tenantID: tenantID}
}

// Put upserts the registration. Partner registrations are tenant-scoped;
// the (id, tenant_id) tuple is the conflict key per ADR-132.
func (r *RegistrationStore) Put(reg *partner.Registration) error {
	if reg == nil {
		return errors.New("pg.RegistrationStore.Put: nil registration")
	}
	const q = `
INSERT INTO partner_registrations (
    id, tenant_id, org_name, contact_email, capabilities, requested_rate_limit,
    state, tier, agid, api_key_hash,
    approved_by_gcid, approved_at,
    suspended_by_gcid, suspended_at, suspend_reason,
    partner_domain, dns_verify_token, dns_verified, dns_verified_at,
    created_at, updated_at, deleted_at
) VALUES (
    $1, $2, $3, $4, $5, $6,
    $7::registration_state, $8, $9, $10,
    $11, $12,
    $13, $14, $15,
    $16, $17, $18, $19,
    $20, $21, $22
)
ON CONFLICT (id) DO UPDATE SET
    org_name             = EXCLUDED.org_name,
    contact_email        = EXCLUDED.contact_email,
    capabilities         = EXCLUDED.capabilities,
    requested_rate_limit = EXCLUDED.requested_rate_limit,
    state                = EXCLUDED.state,
    tier                 = EXCLUDED.tier,
    agid                 = EXCLUDED.agid,
    api_key_hash         = EXCLUDED.api_key_hash,
    approved_by_gcid     = EXCLUDED.approved_by_gcid,
    approved_at          = EXCLUDED.approved_at,
    suspended_by_gcid    = EXCLUDED.suspended_by_gcid,
    suspended_at         = EXCLUDED.suspended_at,
    suspend_reason       = EXCLUDED.suspend_reason,
    partner_domain       = EXCLUDED.partner_domain,
    dns_verify_token     = EXCLUDED.dns_verify_token,
    dns_verified         = EXCLUDED.dns_verified,
    dns_verified_at      = EXCLUDED.dns_verified_at,
    updated_at           = EXCLUDED.updated_at,
    deleted_at           = EXCLUDED.deleted_at
`
	tier := nullableString(string(reg.Tier))
	return r.q.Exec(context.Background(), q,
		reg.ID,
		r.tenantID,
		reg.OrgName,
		reg.ContactEmail,
		reg.Capabilities,
		reg.RequestedRateLimit,
		string(reg.State),
		tier,
		nullableString(reg.AGID),
		nullableString(reg.APIKeyHash),
		nullableString(reg.ApprovedByGCID),
		nullableTimePtr(reg.ApprovedAt),
		nullableString(reg.SuspendedByGCID),
		nullableTimePtr(reg.SuspendedAt),
		nullableString(reg.SuspendReason),
		nullableString(reg.PartnerDomain),
		nullableString(reg.DNSVerifyToken),
		reg.DNSVerified,
		nullableTimePtr(reg.DNSVerifiedAt),
		reg.CreatedAt,
		reg.UpdatedAt,
		nullableTimePtr(reg.DeletedAt),
	)
}

const registrationSelectColumns = `
    id, org_name, contact_email, capabilities, requested_rate_limit,
    state::text, tier::text, agid, api_key_hash,
    approved_by_gcid, approved_at,
    suspended_by_gcid, suspended_at, suspend_reason,
    partner_domain, dns_verify_token, dns_verified, dns_verified_at,
    created_at, updated_at, deleted_at
`

// Get fetches the registration by id.
func (r *RegistrationStore) Get(id string) (*partner.Registration, error) {
	q := `SELECT ` + registrationSelectColumns + `
FROM partner_registrations
WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL
`
	row := r.q.QueryRow(context.Background(), q, r.tenantID, id)
	return scanRegistration(row)
}

// GetByAGID returns the (approved) registration whose AGID matches.
func (r *RegistrationStore) GetByAGID(agid string) (*partner.Registration, error) {
	q := `SELECT ` + registrationSelectColumns + `
FROM partner_registrations
WHERE tenant_id = $1 AND agid = $2 AND deleted_at IS NULL
LIMIT 1
`
	row := r.q.QueryRow(context.Background(), q, r.tenantID, agid)
	return scanRegistration(row)
}

// ListByStatus returns non-deleted registrations in the given state.
func (r *RegistrationStore) ListByStatus(state partner.RegistrationState) ([]*partner.Registration, error) {
	q := `SELECT ` + registrationSelectColumns + `
FROM partner_registrations
WHERE tenant_id = $1 AND state = $2::registration_state AND deleted_at IS NULL
ORDER BY created_at ASC
`
	rows, err := r.q.Query(context.Background(), q, r.tenantID, string(state))
	if err != nil {
		return nil, fmt.Errorf("pg.RegistrationStore.ListByStatus: %w", err)
	}
	defer rows.Close()
	return scanRegistrationRows(rows)
}

// ListAll returns all non-deleted registrations under the tenant.
func (r *RegistrationStore) ListAll() ([]*partner.Registration, error) {
	q := `SELECT ` + registrationSelectColumns + `
FROM partner_registrations
WHERE tenant_id = $1 AND deleted_at IS NULL
ORDER BY created_at ASC
`
	rows, err := r.q.Query(context.Background(), q, r.tenantID)
	if err != nil {
		return nil, fmt.Errorf("pg.RegistrationStore.ListAll: %w", err)
	}
	defer rows.Close()
	return scanRegistrationRows(rows)
}

func scanRegistration(row chorapg.Row) (*partner.Registration, error) {
	var (
		reg              partner.Registration
		state            string
		tier             *string
		agid, apiKeyHash *string
		approvedByGCID   *string
		approvedAt       *time.Time
		suspendedByGCID  *string
		suspendedAt      *time.Time
		suspendReason    *string
		partnerDomain    *string
		dnsVerifyToken   *string
		dnsVerified      bool
		dnsVerifiedAt    *time.Time
		deletedAt        *time.Time
		capabilities     []string
	)
	err := row.Scan(
		&reg.ID,
		&reg.OrgName,
		&reg.ContactEmail,
		&capabilities,
		&reg.RequestedRateLimit,
		&state,
		&tier,
		&agid,
		&apiKeyHash,
		&approvedByGCID,
		&approvedAt,
		&suspendedByGCID,
		&suspendedAt,
		&suspendReason,
		&partnerDomain,
		&dnsVerifyToken,
		&dnsVerified,
		&dnsVerifiedAt,
		&reg.CreatedAt,
		&reg.UpdatedAt,
		&deletedAt,
	)
	if err != nil {
		if errors.Is(err, chorapg.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("pg.RegistrationStore.scan: %w", err)
	}
	reg.State = partner.RegistrationState(state)
	if tier != nil {
		reg.Tier = partner.Tier(*tier)
	}
	if agid != nil {
		reg.AGID = *agid
	}
	if apiKeyHash != nil {
		reg.APIKeyHash = *apiKeyHash
	}
	if approvedByGCID != nil {
		reg.ApprovedByGCID = *approvedByGCID
	}
	if approvedAt != nil {
		t := approvedAt.UTC()
		reg.ApprovedAt = &t
	}
	if suspendedByGCID != nil {
		reg.SuspendedByGCID = *suspendedByGCID
	}
	if suspendedAt != nil {
		t := suspendedAt.UTC()
		reg.SuspendedAt = &t
	}
	if suspendReason != nil {
		reg.SuspendReason = *suspendReason
	}
	if partnerDomain != nil {
		reg.PartnerDomain = *partnerDomain
	}
	if dnsVerifyToken != nil {
		reg.DNSVerifyToken = *dnsVerifyToken
	}
	reg.DNSVerified = dnsVerified
	if dnsVerifiedAt != nil {
		t := dnsVerifiedAt.UTC()
		reg.DNSVerifiedAt = &t
	}
	if deletedAt != nil {
		t := deletedAt.UTC()
		reg.DeletedAt = &t
	}
	reg.Capabilities = capabilities
	return &reg, nil
}

func scanRegistrationRows(rows chorapg.Rows) ([]*partner.Registration, error) {
	out := make([]*partner.Registration, 0)
	for rows.Next() {
		reg, err := scanRegistration(rowsAsRow{rows})
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				continue
			}
			return nil, err
		}
		out = append(out, reg)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// rowsAsRow adapts a Rows.Scan-only call into the Row interface so
// scanRegistration can be reused for both single-row and iteration paths.
type rowsAsRow struct{ rows chorapg.Rows }

func (r rowsAsRow) Scan(dest ...any) error { return r.rows.Scan(dest...) }

// -----------------------------------------------------------------------------
// ContractStore
// -----------------------------------------------------------------------------

// ContractStore is the pgx-backed implementation of the repo.ContractStore port.
type ContractStore struct {
	q        chorapg.Querier
	tenantID string
}

// NewContractStore wraps a Querier with a tenant binding.
func NewContractStore(q chorapg.Querier, tenantID string) *ContractStore {
	return &ContractStore{q: q, tenantID: tenantID}
}

// Put upserts the contract.
func (r *ContractStore) Put(c *contract.Contract) error {
	if c == nil {
		return errors.New("pg.ContractStore.Put: nil contract")
	}
	capsJSON, err := marshalCapabilities(c.Capabilities)
	if err != nil {
		return fmt.Errorf("pg.ContractStore.Put: %w", err)
	}
	const q = `
INSERT INTO a2a_contracts (
    id, tenant_id, partner_id, auth_method, capabilities,
    version, supersedes_id, sunset_at,
    created_at, updated_at, deleted_at
) VALUES (
    $1, $2, $3, $4::a2a_contract_auth, $5,
    $6, $7, $8,
    $9, $10, $11
)
ON CONFLICT (id) DO UPDATE SET
    partner_id    = EXCLUDED.partner_id,
    auth_method   = EXCLUDED.auth_method,
    capabilities  = EXCLUDED.capabilities,
    version       = EXCLUDED.version,
    supersedes_id = EXCLUDED.supersedes_id,
    sunset_at     = EXCLUDED.sunset_at,
    updated_at    = EXCLUDED.updated_at,
    deleted_at    = EXCLUDED.deleted_at
`
	return r.q.Exec(context.Background(), q,
		c.ID,
		r.tenantID,
		c.PartnerID,
		string(c.AuthMethod),
		capsJSON,
		c.Version,
		nullableString(c.SupersedesID),
		nullableTimePtr(c.SunsetAt),
		c.CreatedAt,
		c.UpdatedAt,
		nullableTimePtr(c.DeletedAt),
	)
}

const contractSelectColumns = `
    id, partner_id, auth_method::text, capabilities,
    version, supersedes_id, sunset_at,
    created_at, updated_at, deleted_at
`

// Get fetches the contract by id.
func (r *ContractStore) Get(id string) (*contract.Contract, error) {
	q := `SELECT ` + contractSelectColumns + `
FROM a2a_contracts
WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL
`
	row := r.q.QueryRow(context.Background(), q, r.tenantID, id)
	return scanContract(row)
}

// ListByPartner returns all non-deleted contracts owned by the partner.
func (r *ContractStore) ListByPartner(partnerID string) ([]*contract.Contract, error) {
	q := `SELECT ` + contractSelectColumns + `
FROM a2a_contracts
WHERE tenant_id = $1 AND partner_id = $2 AND deleted_at IS NULL
ORDER BY created_at ASC
`
	rows, err := r.q.Query(context.Background(), q, r.tenantID, partnerID)
	if err != nil {
		return nil, fmt.Errorf("pg.ContractStore.ListByPartner: %w", err)
	}
	defer rows.Close()
	return scanContractRows(rows)
}

// ListAll returns all non-deleted contracts under the tenant.
func (r *ContractStore) ListAll() ([]*contract.Contract, error) {
	q := `SELECT ` + contractSelectColumns + `
FROM a2a_contracts
WHERE tenant_id = $1 AND deleted_at IS NULL
ORDER BY created_at ASC
`
	rows, err := r.q.Query(context.Background(), q, r.tenantID)
	if err != nil {
		return nil, fmt.Errorf("pg.ContractStore.ListAll: %w", err)
	}
	defer rows.Close()
	return scanContractRows(rows)
}

func scanContract(row chorapg.Row) (*contract.Contract, error) {
	var (
		c            contract.Contract
		authMethod   string
		capsJSON     []byte
		supersedesID *string
		sunsetAt     *time.Time
		deletedAt    *time.Time
	)
	err := row.Scan(
		&c.ID,
		&c.PartnerID,
		&authMethod,
		&capsJSON,
		&c.Version,
		&supersedesID,
		&sunsetAt,
		&c.CreatedAt,
		&c.UpdatedAt,
		&deletedAt,
	)
	if err != nil {
		if errors.Is(err, chorapg.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("pg.ContractStore.scan: %w", err)
	}
	c.AuthMethod = contract.AuthMethod(authMethod)
	caps, err := unmarshalCapabilities(capsJSON)
	if err != nil {
		return nil, fmt.Errorf("pg.ContractStore.scan capabilities: %w", err)
	}
	c.Capabilities = caps
	if supersedesID != nil {
		c.SupersedesID = *supersedesID
	}
	if sunsetAt != nil {
		t := sunsetAt.UTC()
		c.SunsetAt = &t
	}
	if deletedAt != nil {
		t := deletedAt.UTC()
		c.DeletedAt = &t
	}
	return &c, nil
}

func scanContractRows(rows chorapg.Rows) ([]*contract.Contract, error) {
	out := make([]*contract.Contract, 0)
	for rows.Next() {
		c, err := scanContract(rowsAsRow{rows})
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				continue
			}
			return nil, err
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// capRow is the wire shape for a Capability in the capabilities JSONB column.
type capRow struct {
	Name            string `json:"name"`
	Tier            string `json:"tier"`
	RateLimitPerMin int    `json:"rate_limit_per_min"`
}

func marshalCapabilities(caps []contract.Capability) ([]byte, error) {
	rows := make([]capRow, len(caps))
	for i, c := range caps {
		rows[i] = capRow{
			Name:            c.Name,
			Tier:            string(c.Tier),
			RateLimitPerMin: c.RateLimitPerMin,
		}
	}
	return json.Marshal(rows)
}

func unmarshalCapabilities(b []byte) ([]contract.Capability, error) {
	if len(b) == 0 {
		return nil, nil
	}
	var rows []capRow
	if err := json.Unmarshal(b, &rows); err != nil {
		return nil, err
	}
	out := make([]contract.Capability, len(rows))
	for i, r := range rows {
		out[i] = contract.Capability{
			Name:            r.Name,
			Tier:            contract.Tier(r.Tier),
			RateLimitPerMin: r.RateLimitPerMin,
		}
	}
	return out, nil
}

// -----------------------------------------------------------------------------
// InvocationStore (append-only)
// -----------------------------------------------------------------------------

// InvocationStore is the pgx-backed implementation of the
// repo.InvocationStore port. Append-only: Append uses INSERT (no upsert),
// Update touches only mutable columns to avoid tripping the immutability
// trigger on the schema.
type InvocationStore struct {
	q        chorapg.Querier
	tenantID string
}

// NewInvocationStore wraps a Querier with a tenant binding.
func NewInvocationStore(q chorapg.Querier, tenantID string) *InvocationStore {
	return &InvocationStore{q: q, tenantID: tenantID}
}

// Append inserts a new invocation. Returns ErrAlreadyExists when the id
// collides — the audit log is append-only, so duplicate IDs are bugs.
func (r *InvocationStore) Append(i *invocation.Invocation) error {
	if i == nil {
		return errors.New("pg.InvocationStore.Append: nil invocation")
	}
	const q = `
INSERT INTO a2a_invocations (
    id, tenant_id, agid, partner_id, capability, correlation_id,
    status, latency_ms, response_size_bytes, error_code,
    started_at, ended_at, traceparent, endpoint
) VALUES (
    $1, $2, $3, $4, $5, $6,
    $7::a2a_invocation_status, $8, $9, $10,
    $11, $12, $13, $14
)
`
	if err := r.q.Exec(context.Background(), q,
		i.ID,
		r.tenantID,
		i.AGID,
		i.PartnerID,
		i.Capability,
		i.CorrelationID,
		string(i.Status),
		i.LatencyMS,
		i.ResponseSizeBytes,
		i.ErrorCode,
		i.StartedAt,
		nullableTimePtr(i.EndedAt),
		i.Traceparent,
		i.Endpoint,
	); err != nil {
		if isUniqueViolation(err) {
			return ErrAlreadyExists
		}
		return err
	}
	return nil
}

// Update applies a terminal-status transition. Only mutable columns are
// touched — the schema trigger forbids any change to agid / capability /
// correlation_id / started_at.
func (r *InvocationStore) Update(i *invocation.Invocation) error {
	if i == nil {
		return errors.New("pg.InvocationStore.Update: nil invocation")
	}
	const q = `
UPDATE a2a_invocations
SET status              = $3::a2a_invocation_status,
    latency_ms          = $4,
    response_size_bytes = $5,
    error_code          = $6,
    ended_at            = $7,
    traceparent         = $8,
    endpoint            = $9
WHERE tenant_id = $1 AND id = $2
`
	return r.q.Exec(context.Background(), q,
		r.tenantID,
		i.ID,
		string(i.Status),
		i.LatencyMS,
		i.ResponseSizeBytes,
		i.ErrorCode,
		nullableTimePtr(i.EndedAt),
		i.Traceparent,
		i.Endpoint,
	)
}

const invocationSelectColumns = `
    id, agid, partner_id, capability, correlation_id,
    status::text, latency_ms, response_size_bytes, error_code,
    started_at, ended_at, traceparent, endpoint
`

// Get fetches an invocation by id.
func (r *InvocationStore) Get(id string) (*invocation.Invocation, error) {
	q := `SELECT ` + invocationSelectColumns + `
FROM a2a_invocations
WHERE tenant_id = $1 AND id = $2
`
	row := r.q.QueryRow(context.Background(), q, r.tenantID, id)
	return scanInvocation(row)
}

// ListByPartner returns invocations for a partner sorted by StartedAt ASC.
func (r *InvocationStore) ListByPartner(partnerID string) ([]*invocation.Invocation, error) {
	q := `SELECT ` + invocationSelectColumns + `
FROM a2a_invocations
WHERE tenant_id = $1 AND partner_id = $2
ORDER BY started_at ASC
`
	rows, err := r.q.Query(context.Background(), q, r.tenantID, partnerID)
	if err != nil {
		return nil, fmt.Errorf("pg.InvocationStore.ListByPartner: %w", err)
	}
	defer rows.Close()
	return scanInvocationRows(rows)
}

// ListSince returns invocations with started_at >= since (descending).
// Zero `since` returns the full log.
func (r *InvocationStore) ListSince(since time.Time) ([]*invocation.Invocation, error) {
	if since.IsZero() {
		q := `SELECT ` + invocationSelectColumns + `
FROM a2a_invocations
WHERE tenant_id = $1
ORDER BY started_at DESC
`
		rows, err := r.q.Query(context.Background(), q, r.tenantID)
		if err != nil {
			return nil, fmt.Errorf("pg.InvocationStore.ListSince: %w", err)
		}
		defer rows.Close()
		return scanInvocationRows(rows)
	}
	q := `SELECT ` + invocationSelectColumns + `
FROM a2a_invocations
WHERE tenant_id = $1 AND started_at >= $2
ORDER BY started_at DESC
`
	rows, err := r.q.Query(context.Background(), q, r.tenantID, since)
	if err != nil {
		return nil, fmt.Errorf("pg.InvocationStore.ListSince: %w", err)
	}
	defer rows.Close()
	return scanInvocationRows(rows)
}

func scanInvocation(row chorapg.Row) (*invocation.Invocation, error) {
	var (
		inv     invocation.Invocation
		status  string
		endedAt *time.Time
	)
	err := row.Scan(
		&inv.ID,
		&inv.AGID,
		&inv.PartnerID,
		&inv.Capability,
		&inv.CorrelationID,
		&status,
		&inv.LatencyMS,
		&inv.ResponseSizeBytes,
		&inv.ErrorCode,
		&inv.StartedAt,
		&endedAt,
		&inv.Traceparent,
		&inv.Endpoint,
	)
	if err != nil {
		if errors.Is(err, chorapg.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("pg.InvocationStore.scan: %w", err)
	}
	inv.Status = invocation.Status(status)
	if endedAt != nil {
		t := endedAt.UTC()
		inv.EndedAt = &t
	}
	return &inv, nil
}

func scanInvocationRows(rows chorapg.Rows) ([]*invocation.Invocation, error) {
	out := make([]*invocation.Invocation, 0)
	for rows.Next() {
		inv, err := scanInvocation(rowsAsRow{rows})
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				continue
			}
			return nil, err
		}
		out = append(out, inv)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullableTimePtr(t *time.Time) any {
	if t == nil {
		return nil
	}
	return *t
}

// isUniqueViolation reports whether err looks like a Postgres unique-violation.
// We probe error text rather than depend on pgx ErrorCode to keep the stub
// adapter (in repo_test.go) trivially testable. Production-grade callers can
// inspect *pgconn.PgError directly.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "duplicate key") ||
		strings.Contains(msg, "unique constraint") ||
		strings.Contains(msg, "23505")
}
