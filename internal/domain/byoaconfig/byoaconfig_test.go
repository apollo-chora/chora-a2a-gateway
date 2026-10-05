// Package byoaconfig_test exercises the BYOA configuration service relocated
// from chora-familiar legacy per ADR-132 (A2A is the sole sanctioned external
// cross-project sync path) and the M12.2 Batch 4 BYOA relocation flag.
//
// CRITICAL invariants preserved from the legacy port:
//   - api_key_ref MUST be encrypted reference (prefix "enc:"); raw keys rejected
//   - Governance Gatekeeper override is NOT mutable here — this layer only
//     persists tenant+gcid scoped LLM config; the Gatekeeper ALWAYS uses the
//     platform-controlled model regardless of BYOA config (per CLAUDE.md
//     Principle Conflict Resolution: BYOA Sovereignty vs Governance → Governance wins)
//   - event bus publish uses chora.a2a.byoa.* topic (relocated from chora.familiar.events)
//
// Tests use stdlib testing only (matches chora-a2a-gateway's existing style;
// no testify). Mocks are hand-rolled to satisfy ConfigRepository + EventPublisher.
package byoaconfig_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/byoaconfig"
)

// ---------------------------------------------------------------------------
// Hand-rolled mocks (chora-a2a-gateway style: stdlib testing, no testify)
// ---------------------------------------------------------------------------

type fakeConfigRepo struct {
	getResult  *byoaconfig.Config
	getErr     error
	createErr  error
	updateErr  error
	deleteErr  error
	createCall int
	updateCall int
	deleteCall int
	lastCreate *byoaconfig.Config
	lastUpdate *byoaconfig.Config
	lastDelete uuid.UUID
}

func (f *fakeConfigRepo) Create(_ context.Context, c *byoaconfig.Config) error {
	f.createCall++
	f.lastCreate = c
	return f.createErr
}

func (f *fakeConfigRepo) GetByGCID(_ context.Context, _ uuid.UUID) (*byoaconfig.Config, error) {
	return f.getResult, f.getErr
}

func (f *fakeConfigRepo) GetByTenantAndGCID(_ context.Context, _ uuid.UUID, _ uuid.UUID) (*byoaconfig.Config, error) {
	return f.getResult, f.getErr
}

func (f *fakeConfigRepo) Update(_ context.Context, c *byoaconfig.Config) error {
	f.updateCall++
	f.lastUpdate = c
	return f.updateErr
}

func (f *fakeConfigRepo) Delete(_ context.Context, id uuid.UUID) error {
	f.deleteCall++
	f.lastDelete = id
	return f.deleteErr
}

type fakePublisher struct {
	calls     int
	lastTopic string
	lastEvent byoaconfig.DomainEvent
	err       error
}

func (f *fakePublisher) Publish(_ context.Context, topic string, evt byoaconfig.DomainEvent) error {
	f.calls++
	f.lastTopic = topic
	f.lastEvent = evt
	return f.err
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

func validConfig() *byoaconfig.Config {
	return &byoaconfig.Config{
		TenantID:    uuid.Must(uuid.NewV7()),
		GCID:        uuid.Must(uuid.NewV7()),
		Provider:    byoaconfig.ProviderOpenAI,
		ModelID:     "gpt-4o",
		APIKeyRef:   "enc:vault/openai/key-123",
		Temperature: 0.7,
		MaxTokens:   4096,
		IsActive:    true,
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestService_SetConfig_CreateNew(t *testing.T) {
	t.Parallel()
	repo := &fakeConfigRepo{getErr: byoaconfig.ErrConfigNotFound}
	pub := &fakePublisher{}
	svc := byoaconfig.NewService(repo, pub)
	ctx := context.Background()

	cfg := validConfig()
	result, err := svc.SetConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("SetConfig: %v", err)
	}
	if result.ID == uuid.Nil {
		t.Errorf("expected ID assigned")
	}
	if result.Provider != byoaconfig.ProviderOpenAI {
		t.Errorf("provider: got %s want %s", result.Provider, byoaconfig.ProviderOpenAI)
	}
	if result.ModelID != "gpt-4o" {
		t.Errorf("model: got %q", result.ModelID)
	}
	if !result.IsActive {
		t.Errorf("expected IsActive")
	}
	if repo.createCall != 1 {
		t.Errorf("Create calls = %d, want 1", repo.createCall)
	}
	if pub.calls != 1 {
		t.Errorf("Publish calls = %d, want 1", pub.calls)
	}
	if pub.lastTopic != byoaconfig.TopicBYOAEvents {
		t.Errorf("topic: got %q want %q", pub.lastTopic, byoaconfig.TopicBYOAEvents)
	}
	if pub.lastEvent.EventType != byoaconfig.EventConfigUpdated {
		t.Errorf("event type: got %q want %q", pub.lastEvent.EventType, byoaconfig.EventConfigUpdated)
	}
}

func TestService_SetConfig_UpdateExisting(t *testing.T) {
	t.Parallel()
	cfg := validConfig()
	existing := &byoaconfig.Config{
		ID:        uuid.Must(uuid.NewV7()),
		TenantID:  cfg.TenantID,
		GCID:      cfg.GCID,
		Provider:  byoaconfig.ProviderGoogle,
		ModelID:   "gemini-1.5-pro",
		APIKeyRef: "enc:vault/google/old-key",
	}
	repo := &fakeConfigRepo{getResult: existing}
	pub := &fakePublisher{}
	svc := byoaconfig.NewService(repo, pub)

	result, err := svc.SetConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("SetConfig: %v", err)
	}
	if result.ID != existing.ID {
		t.Errorf("ID changed: got %s want %s", result.ID, existing.ID)
	}
	if result.Provider != byoaconfig.ProviderOpenAI {
		t.Errorf("provider not updated")
	}
	if result.ModelID != "gpt-4o" {
		t.Errorf("model not updated")
	}
	if repo.updateCall != 1 {
		t.Errorf("Update calls = %d, want 1", repo.updateCall)
	}
	if repo.createCall != 0 {
		t.Errorf("Create unexpectedly called")
	}
}

func TestService_SetConfig_RejectRawAPIKey(t *testing.T) {
	t.Parallel()
	repo := &fakeConfigRepo{getErr: byoaconfig.ErrConfigNotFound}
	pub := &fakePublisher{}
	svc := byoaconfig.NewService(repo, pub)

	cfg := validConfig()
	cfg.APIKeyRef = "sk-raw-api-key-12345" // no enc: prefix

	if _, err := svc.SetConfig(context.Background(), cfg); !errors.Is(err, byoaconfig.ErrRawAPIKey) {
		t.Errorf("expected ErrRawAPIKey, got %v", err)
	}
}

func TestService_SetConfig_EmptyAPIKeyRef(t *testing.T) {
	t.Parallel()
	repo := &fakeConfigRepo{getErr: byoaconfig.ErrConfigNotFound}
	pub := &fakePublisher{}
	svc := byoaconfig.NewService(repo, pub)

	cfg := validConfig()
	cfg.APIKeyRef = ""

	if _, err := svc.SetConfig(context.Background(), cfg); !errors.Is(err, byoaconfig.ErrValidationFailed) {
		t.Errorf("expected ErrValidationFailed, got %v", err)
	}
}

func TestService_SetConfig_InvalidProvider(t *testing.T) {
	t.Parallel()
	repo := &fakeConfigRepo{getErr: byoaconfig.ErrConfigNotFound}
	pub := &fakePublisher{}
	svc := byoaconfig.NewService(repo, pub)

	cfg := validConfig()
	cfg.Provider = byoaconfig.Provider("invalid")

	if _, err := svc.SetConfig(context.Background(), cfg); !errors.Is(err, byoaconfig.ErrInvalidProvider) {
		t.Errorf("expected ErrInvalidProvider, got %v", err)
	}
}

func TestService_SetConfig_EmptyModelID(t *testing.T) {
	t.Parallel()
	repo := &fakeConfigRepo{getErr: byoaconfig.ErrConfigNotFound}
	pub := &fakePublisher{}
	svc := byoaconfig.NewService(repo, pub)

	cfg := validConfig()
	cfg.ModelID = ""

	if _, err := svc.SetConfig(context.Background(), cfg); !errors.Is(err, byoaconfig.ErrValidationFailed) {
		t.Errorf("expected ErrValidationFailed, got %v", err)
	}
}

func TestService_SetConfig_TemperatureOutOfRange(t *testing.T) {
	t.Parallel()
	repo := &fakeConfigRepo{getErr: byoaconfig.ErrConfigNotFound}
	pub := &fakePublisher{}
	svc := byoaconfig.NewService(repo, pub)

	cfg := validConfig()
	cfg.Temperature = 2.5

	if _, err := svc.SetConfig(context.Background(), cfg); !errors.Is(err, byoaconfig.ErrValidationFailed) {
		t.Errorf("expected ErrValidationFailed, got %v", err)
	}
}

func TestService_SetConfig_MaxTokensOutOfRange(t *testing.T) {
	t.Parallel()
	repo := &fakeConfigRepo{getErr: byoaconfig.ErrConfigNotFound}
	pub := &fakePublisher{}
	svc := byoaconfig.NewService(repo, pub)

	cfg := validConfig()
	cfg.MaxTokens = 0

	if _, err := svc.SetConfig(context.Background(), cfg); !errors.Is(err, byoaconfig.ErrValidationFailed) {
		t.Errorf("expected ErrValidationFailed, got %v", err)
	}
}

func TestService_SetConfig_TenantIDRequired(t *testing.T) {
	t.Parallel()
	repo := &fakeConfigRepo{getErr: byoaconfig.ErrConfigNotFound}
	pub := &fakePublisher{}
	svc := byoaconfig.NewService(repo, pub)

	cfg := validConfig()
	cfg.TenantID = uuid.Nil

	if _, err := svc.SetConfig(context.Background(), cfg); !errors.Is(err, byoaconfig.ErrValidationFailed) {
		t.Errorf("expected ErrValidationFailed, got %v", err)
	}
}

func TestService_SetConfig_GCIDRequired(t *testing.T) {
	t.Parallel()
	repo := &fakeConfigRepo{getErr: byoaconfig.ErrConfigNotFound}
	pub := &fakePublisher{}
	svc := byoaconfig.NewService(repo, pub)

	cfg := validConfig()
	cfg.GCID = uuid.Nil

	if _, err := svc.SetConfig(context.Background(), cfg); !errors.Is(err, byoaconfig.ErrValidationFailed) {
		t.Errorf("expected ErrValidationFailed, got %v", err)
	}
}

func TestService_GetConfig(t *testing.T) {
	t.Parallel()
	tenantID := uuid.Must(uuid.NewV7())
	gcid := uuid.Must(uuid.NewV7())
	expected := &byoaconfig.Config{
		ID:       uuid.Must(uuid.NewV7()),
		TenantID: tenantID,
		GCID:     gcid,
		Provider: byoaconfig.ProviderAnthropic,
		ModelID:  "claude-sonnet-4-20250514",
	}
	repo := &fakeConfigRepo{getResult: expected}
	pub := &fakePublisher{}
	svc := byoaconfig.NewService(repo, pub)

	result, err := svc.GetConfig(context.Background(), tenantID, gcid)
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	if result.ID != expected.ID {
		t.Errorf("ID mismatch")
	}
}

func TestService_GetConfig_NilIDs(t *testing.T) {
	t.Parallel()
	repo := &fakeConfigRepo{}
	pub := &fakePublisher{}
	svc := byoaconfig.NewService(repo, pub)

	if _, err := svc.GetConfig(context.Background(), uuid.Nil, uuid.Must(uuid.NewV7())); !errors.Is(err, byoaconfig.ErrValidationFailed) {
		t.Errorf("expected ErrValidationFailed, got %v", err)
	}
	if _, err := svc.GetConfig(context.Background(), uuid.Must(uuid.NewV7()), uuid.Nil); !errors.Is(err, byoaconfig.ErrValidationFailed) {
		t.Errorf("expected ErrValidationFailed, got %v", err)
	}
}

func TestService_ValidateConfig(t *testing.T) {
	t.Parallel()
	repo := &fakeConfigRepo{}
	pub := &fakePublisher{}
	svc := byoaconfig.NewService(repo, pub)

	if err := svc.ValidateConfig(validConfig()); err != nil {
		t.Errorf("ValidateConfig on valid config: %v", err)
	}
}

func TestService_ListProviders(t *testing.T) {
	t.Parallel()
	repo := &fakeConfigRepo{}
	pub := &fakePublisher{}
	svc := byoaconfig.NewService(repo, pub)

	providers := svc.ListProviders()
	if len(providers) != 4 {
		t.Fatalf("len(providers) = %d, want 4", len(providers))
	}
	if providers[0].Provider != byoaconfig.ProviderOpenAI {
		t.Errorf("first provider = %s, want openai", providers[0].Provider)
	}
	found := false
	for _, m := range providers[0].Models {
		if m == "gpt-4o" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("openai models missing gpt-4o")
	}
}

func TestService_DeleteConfig(t *testing.T) {
	t.Parallel()
	repo := &fakeConfigRepo{}
	pub := &fakePublisher{}
	svc := byoaconfig.NewService(repo, pub)

	id := uuid.Must(uuid.NewV7())
	if err := svc.DeleteConfig(context.Background(), id); err != nil {
		t.Fatalf("DeleteConfig: %v", err)
	}
	if repo.deleteCall != 1 {
		t.Errorf("Delete calls = %d, want 1", repo.deleteCall)
	}
	if repo.lastDelete != id {
		t.Errorf("delete id mismatch")
	}
}

func TestService_DeleteConfig_NilID(t *testing.T) {
	t.Parallel()
	repo := &fakeConfigRepo{}
	pub := &fakePublisher{}
	svc := byoaconfig.NewService(repo, pub)

	if err := svc.DeleteConfig(context.Background(), uuid.Nil); !errors.Is(err, byoaconfig.ErrValidationFailed) {
		t.Errorf("expected ErrValidationFailed, got %v", err)
	}
}

// Provider IsValid: each canonical provider passes; unknown fails.
func TestProvider_IsValid(t *testing.T) {
	t.Parallel()
	valid := []byoaconfig.Provider{
		byoaconfig.ProviderOpenAI,
		byoaconfig.ProviderAnthropic,
		byoaconfig.ProviderGoogle,
		byoaconfig.ProviderCustom,
	}
	for _, p := range valid {
		if !p.IsValid() {
			t.Errorf("provider %q expected valid", p)
		}
	}
	if byoaconfig.Provider("nonsense").IsValid() {
		t.Errorf("nonsense provider unexpectedly valid")
	}
}
