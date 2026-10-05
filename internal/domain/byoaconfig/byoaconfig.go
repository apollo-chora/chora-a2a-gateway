// Package byoaconfig implements the high-level Bring Your Own Agent (BYOA)
// configuration management primitive per ADR-132 (A2A is the sole sanctioned
// external cross-project sync path) + M12.2 Batch 4 relocation flag.
//
// Relocated from chora-familiar/internal/domain/byoa_service.go (legacy)
// 2026-05-12. The legacy chora-familiar dir will be archived by Batch 5.
//
// CRITICAL invariants:
//   - Config.APIKeyRef MUST be an encrypted reference (prefix "enc:");
//     raw API keys are rejected (ErrRawAPIKey). The low-level AES-GCM
//     vault primitive (this service's internal/domain/byoa package)
//     produces the ciphertext; this layer persists only the indirection ref
//   - Governance Gatekeeper override is NOT possible via this layer —
//     the Gatekeeper ALWAYS uses the platform-controlled model regardless
//     of BYOA config (CLAUDE.md §5 Principle Conflict Resolution:
//     "BYOA Sovereignty vs Governance → Governance wins")
//   - event bus topic is chora.a2a.byoa.events (relocated from chora.familiar.events)
//   - Per chora-a2a-gateway/migrations/0001_initial.sql convention, RLS uses
//     current_setting('chora.tenant_id', true)::uuid
//
// Hexagonal: this package is the DOMAIN layer. No infrastructure imports.
// Adapters (postgres / pubsub / HTTP) live under internal/adapter/ and
// satisfy the ConfigRepository + EventPublisher interfaces here.
package byoaconfig

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

// Sentinel errors. Error codes prefixed with A2A_BYOA_ (relocated from
// FAMILIAR_BYOA_ to reflect new owning domain).
var (
	ErrConfigNotFound   = errors.New("A2A_BYOA_CONFIG_NOT_FOUND")
	ErrInvalidProvider  = errors.New("A2A_BYOA_INVALID_PROVIDER")
	ErrRawAPIKey        = errors.New("A2A_BYOA_RAW_API_KEY_REJECTED")
	ErrValidationFailed = errors.New("A2A_BYOA_VALIDATION_FAILED")
)

// APIKeyRefPrefix is the required prefix for encrypted API key references.
// Raw API keys are NEVER stored — only encrypted references. The plaintext
// is encrypted via the low-level byoa package (AES-GCM + tenant master key
// from Cloud KMS CMEK in production).
const APIKeyRefPrefix = "enc:"

// ---------------------------------------------------------------------------
// Provider enum
// ---------------------------------------------------------------------------

// Provider represents the upstream LLM provider hosting the BYOA model.
type Provider string

const (
	ProviderOpenAI    Provider = "openai"
	ProviderAnthropic Provider = "anthropic"
	ProviderGoogle    Provider = "google"
	ProviderCustom    Provider = "custom"
)

// IsValid returns true if the Provider value is recognized.
func (p Provider) IsValid() bool {
	switch p {
	case ProviderOpenAI, ProviderAnthropic, ProviderGoogle, ProviderCustom:
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// Aggregates
// ---------------------------------------------------------------------------

// Config represents a Bring Your Own Agent model configuration aggregate.
// One active row per (tenant_id, gcid) (enforced by partial unique index).
//
// CRITICAL: APIKeyRef is an encrypted reference, NEVER a raw API key.
type Config struct {
	ID                   uuid.UUID  `json:"id"`
	TenantID             uuid.UUID  `json:"tenant_id"`
	GCID                 uuid.UUID  `json:"gcid"`
	Provider             Provider   `json:"provider"`
	ModelID              string     `json:"model_id"`
	APIKeyRef            string     `json:"api_key_ref"` // Encrypted reference — NEVER raw
	Temperature          float64    `json:"temperature"`
	MaxTokens            int        `json:"max_tokens"`
	SystemPromptOverride *string    `json:"system_prompt_override,omitempty"`
	IsActive             bool       `json:"is_active"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
	DeletedAt            *time.Time `json:"deleted_at,omitempty"`
}

// SupportedProvider describes a provider and its catalog of available models.
type SupportedProvider struct {
	Provider Provider `json:"provider"`
	Models   []string `json:"models"`
}

// ---------------------------------------------------------------------------
// Domain events (event bus envelope; outbox wiring lands in M12.3)
// ---------------------------------------------------------------------------

// event bus topic + event-type constants. Relocated from chora.familiar.events
// to the chora.a2a.* prefix per ADR-132 + pub-sub-topology canonical naming
// (chora.{domain}.{aggregate}.{event_type}.v{N}).
const (
	TopicBYOAEvents     = "chora.a2a.byoa.events"
	EventConfigUpdated  = "chora.a2a.byoa.config.updated.v1"
	EventConfigRevoked  = "chora.a2a.byoa.config.revoked.v1"
	AggregateBYOAConfig = "BYOAConfig"
)

// DomainEvent is the envelope published to chora.a2a.byoa.events. M12.3 wires
// the canonical envelope (event_id, idempotency_key, traceparent, tracestate,
// source_project, schema_version) via the outbox; this skeleton carries the
// minimum payload to preserve the legacy publish-call shape.
type DomainEvent struct {
	EventID       uuid.UUID              `json:"event_id"`
	EventType     string                 `json:"event_type"`
	Timestamp     time.Time              `json:"timestamp"`
	TenantID      *uuid.UUID             `json:"tenant_id,omitempty"`
	GCID          *uuid.UUID             `json:"gcid,omitempty"`
	AggregateID   uuid.UUID              `json:"aggregate_id"`
	AggregateType string                 `json:"aggregate_type"`
	Payload       map[string]interface{} `json:"payload"`
}

// NewDomainEvent constructs an event with a generated UUIDv7 + UTC timestamp.
func NewDomainEvent(
	eventType string,
	tenantID, gcid *uuid.UUID,
	aggregateID uuid.UUID,
	aggregateType string,
	payload map[string]interface{},
) DomainEvent {
	return DomainEvent{
		EventID:       uuid.Must(uuid.NewV7()),
		EventType:     eventType,
		Timestamp:     time.Now().UTC(),
		TenantID:      tenantID,
		GCID:          gcid,
		AggregateID:   aggregateID,
		AggregateType: aggregateType,
		Payload:       payload,
	}
}

// ---------------------------------------------------------------------------
// Ports (interfaces implemented by adapters)
// ---------------------------------------------------------------------------

// ConfigRepository persists BYOA configurations. Adapters live under
// internal/adapter/pg/ (Postgres chora_a2a) or internal/adapter/inmem/.
type ConfigRepository interface {
	Create(ctx context.Context, c *Config) error
	GetByGCID(ctx context.Context, gcid uuid.UUID) (*Config, error)
	GetByTenantAndGCID(ctx context.Context, tenantID, gcid uuid.UUID) (*Config, error)
	Update(ctx context.Context, c *Config) error
	Delete(ctx context.Context, id uuid.UUID) error
}

// EventPublisher abstracts event bus. The production adapter wires the
// chora-go-common outbox PostgresRecorder + Relay so config-write +
// event-publish are atomic (D6 Pillar 2: outbox delivery resilience).
type EventPublisher interface {
	Publish(ctx context.Context, topic string, event DomainEvent) error
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

// Service manages BYOA configurations. It enforces:
//   - encrypted API-key references only (raw rejected)
//   - one active config per (tenant, gcid)
//   - idempotent create-or-update semantics
//
// The Governance Gatekeeper override is intentionally absent: the Gatekeeper
// always uses the platform-controlled model regardless of any BYOA config
// (Principle Conflict Resolution: Governance wins over BYOA Sovereignty).
type Service struct {
	repo ConfigRepository
	pub  EventPublisher
}

// NewService constructs a Service. Both dependencies are required.
func NewService(repo ConfigRepository, pub EventPublisher) *Service {
	return &Service{repo: repo, pub: pub}
}

// SetConfig creates or updates a BYOA configuration for a learner. Idempotent
// on (tenant_id, gcid). Validates the config before touching the repository.
func (s *Service) SetConfig(ctx context.Context, c *Config) (*Config, error) {
	if err := s.validate(c); err != nil {
		return nil, err
	}

	now := time.Now().UTC()

	existing, err := s.repo.GetByTenantAndGCID(ctx, c.TenantID, c.GCID)
	if err != nil && !errors.Is(err, ErrConfigNotFound) {
		return nil, fmt.Errorf("check existing BYOA config: %w", err)
	}

	if existing != nil {
		existing.Provider = c.Provider
		existing.ModelID = c.ModelID
		existing.APIKeyRef = c.APIKeyRef
		existing.Temperature = c.Temperature
		existing.MaxTokens = c.MaxTokens
		existing.SystemPromptOverride = c.SystemPromptOverride
		existing.IsActive = c.IsActive
		existing.UpdatedAt = now

		if err := s.repo.Update(ctx, existing); err != nil {
			return nil, fmt.Errorf("update BYOA config: %w", err)
		}
		s.publishUpdated(ctx, existing)
		return existing, nil
	}

	c.ID = uuid.Must(uuid.NewV7())
	c.CreatedAt = now
	c.UpdatedAt = now

	if err := s.repo.Create(ctx, c); err != nil {
		return nil, fmt.Errorf("create BYOA config: %w", err)
	}
	s.publishUpdated(ctx, c)
	return c, nil
}

// GetConfig retrieves the active BYOA configuration for a learner in a tenant.
func (s *Service) GetConfig(ctx context.Context, tenantID, gcid uuid.UUID) (*Config, error) {
	if tenantID == uuid.Nil || gcid == uuid.Nil {
		return nil, ErrValidationFailed
	}
	return s.repo.GetByTenantAndGCID(ctx, tenantID, gcid)
}

// ValidateConfig validates a configuration without persisting it.
func (s *Service) ValidateConfig(c *Config) error {
	return s.validate(c)
}

// ListProviders returns the supported BYOA providers and their model catalog.
// Catalogs are intentionally static here; M12.3 will source them from a
// chora_a2a `byoa_provider_catalog` table.
func (s *Service) ListProviders() []SupportedProvider {
	return []SupportedProvider{
		{
			Provider: ProviderOpenAI,
			Models:   []string{"gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-3.5-turbo"},
		},
		{
			Provider: ProviderAnthropic,
			Models:   []string{"claude-sonnet-4-20250514", "claude-3-5-haiku-20241022", "claude-3-opus-20240229"},
		},
		{
			Provider: ProviderGoogle,
			Models:   []string{"gemini-2.0-flash", "gemini-1.5-pro", "gemini-1.5-flash"},
		},
		{
			Provider: ProviderCustom,
			Models:   []string{}, // user-specified
		},
	}
}

// DeleteConfig soft-deletes a BYOA configuration.
func (s *Service) DeleteConfig(ctx context.Context, id uuid.UUID) error {
	if id == uuid.Nil {
		return ErrValidationFailed
	}
	return s.repo.Delete(ctx, id)
}

// ---------------------------------------------------------------------------
// internals
// ---------------------------------------------------------------------------

func (s *Service) validate(c *Config) error {
	if c == nil {
		return ErrValidationFailed
	}
	if c.TenantID == uuid.Nil || c.GCID == uuid.Nil {
		return ErrValidationFailed
	}
	if !c.Provider.IsValid() {
		return ErrInvalidProvider
	}
	if c.ModelID == "" {
		return ErrValidationFailed
	}

	// CRITICAL: reject raw API keys. Only encrypted references are accepted.
	if c.APIKeyRef == "" {
		return ErrValidationFailed
	}
	if !strings.HasPrefix(c.APIKeyRef, APIKeyRefPrefix) {
		return ErrRawAPIKey
	}

	if c.Temperature < 0 || c.Temperature > 2 {
		return ErrValidationFailed
	}
	if c.MaxTokens <= 0 || c.MaxTokens > 128000 {
		return ErrValidationFailed
	}
	return nil
}

func (s *Service) publishUpdated(ctx context.Context, c *Config) {
	tenantID, gcid := c.TenantID, c.GCID
	evt := NewDomainEvent(
		EventConfigUpdated,
		&tenantID,
		&gcid,
		c.ID,
		AggregateBYOAConfig,
		map[string]interface{}{
			"provider":  string(c.Provider),
			"model_id":  c.ModelID,
			"is_active": c.IsActive,
		},
	)
	// Best-effort publish (legacy parity). M12.3 wires the outbox so this
	// becomes atomic with the DB write.
	_ = s.pub.Publish(ctx, TopicBYOAEvents, evt)
}
