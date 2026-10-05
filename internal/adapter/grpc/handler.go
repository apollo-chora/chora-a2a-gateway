// Package grpcadapter — handler.go: bridges the gRPC InvokerServer to the
// same business logic the REST ExtRouter uses (registrations, contracts,
// invocations, rate-limiter, events publisher).
//
// This is the production handler — production CMD wires this against the
// real Postgres / event bus adapters. Tests can mock the handler via the
// InvokerHandler interface (see server_test.go for stubHandler).
package grpcadapter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/events"
	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/rate_limiter"
	"github.com/apollo-chora/chora-a2a-gateway/internal/adapter/repo"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/contract"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/invocation"
	"github.com/apollo-chora/chora-a2a-gateway/internal/domain/partner"
)

// HandlerConfig is the dependency bundle for the production handler.
type HandlerConfig struct {
	Registrations repo.RegistrationStore
	Contracts     repo.ContractStore
	Invocations   repo.InvocationStore
	Publisher     events.Publisher
	RateLimiter   *rate_limiter.TokenBucket
}

// Handler is the production InvokerHandler, sharing state with the REST
// adapter so a Chora-side caller invoking via gRPC sees the same audit
// trail / rate-limit counter as a partner invoking via REST.
type Handler struct {
	cfg HandlerConfig
}

// NewHandler constructs a new production handler.
func NewHandler(cfg HandlerConfig) *Handler {
	return &Handler{cfg: cfg}
}

// Invoke matches the REST /a2a/invoke flow:
//   - validate API key against the registration
//   - reject suspended partners (403)
//   - check capability is in an active contract (else scope_denied)
//   - rate-limit per-AGID (else rate_limited)
//   - record append-only invocation + emit chora.a2a.invocation.completed.v1
func (h *Handler) Invoke(ctx context.Context, req *InvokeRequest) (*InvokeResponse, error) {
	reg, err := h.cfg.Registrations.Get(req.PartnerID)
	if errors.Is(err, repo.ErrNotFound) {
		return nil, errInvalidAPIKey
	}
	if err != nil {
		return nil, fmt.Errorf("grpc invoke: lookup partner: %w", err)
	}
	if !verifyKeyHash(reg, req.APIKey) {
		return nil, errInvalidAPIKey
	}
	if !reg.IsActive() {
		return nil, errPartnerSuspended
	}

	cs, _ := h.cfg.Contracts.ListByPartner(req.PartnerID)
	var grantedCap *contract.Capability
	var grantedContract *contract.Contract
	for _, c := range cs {
		if !c.IsActive() {
			continue
		}
		for i, cap := range c.Capabilities {
			if cap.Name == req.Capability {
				grantedCap = &c.Capabilities[i]
				grantedContract = c
				break
			}
		}
		if grantedCap != nil {
			break
		}
	}
	tenantID := req.TenantID
	if tenantID == "" {
		tenantID = "platform"
	}
	if grantedCap == nil {
		inv := mustNewInvocation(reg, req.Capability, req.CorrelationID, req.Traceparent)
		_ = inv.ScopeDeny("CAPABILITY_NOT_IN_CONTRACT")
		_ = h.cfg.Invocations.Append(inv)
		_ = h.cfg.Publisher.Publish(events.Event{
			Topic: "chora.a2a.invocation.scope_denied.v1",
			Payload: map[string]any{
				"invocation_id": inv.ID, "agid": inv.AGID, "capability": inv.Capability,
				"partner_id": inv.PartnerID, "correlation_id": inv.CorrelationID,
			},
			TenantID: tenantID, Traceparent: req.Traceparent,
			IMDADimension: "fairness_and_human_oversight", IMDALifecycleStage: "runtime",
		})
		return &InvokeResponse{
			InvocationID: inv.ID, Status: "scope_denied", ErrorCode: "SCOPE_DENIED",
		}, nil
	}

	if h.cfg.RateLimiter != nil && !h.cfg.RateLimiter.Allow(reg.AGID) {
		inv := mustNewInvocation(reg, req.Capability, req.CorrelationID, req.Traceparent)
		_ = inv.RateLimit()
		_ = h.cfg.Invocations.Append(inv)
		_ = h.cfg.Publisher.Publish(events.Event{
			Topic: "chora.a2a.invocation.rate_limited.v1",
			Payload: map[string]any{
				"invocation_id": inv.ID, "agid": inv.AGID, "capability": inv.Capability,
				"partner_id": inv.PartnerID, "correlation_id": inv.CorrelationID,
			},
			TenantID: tenantID, Traceparent: req.Traceparent,
			IMDADimension: "fairness_and_human_oversight", IMDALifecycleStage: "runtime",
		})
		return &InvokeResponse{
			InvocationID: inv.ID, Status: "rate_limited", ErrorCode: "RATE_LIMITED",
		}, nil
	}

	inv := mustNewInvocation(reg, req.Capability, req.CorrelationID, req.Traceparent)
	if err := h.cfg.Invocations.Append(inv); err != nil {
		return nil, fmt.Errorf("grpc invoke: append invocation: %w", err)
	}
	_ = inv.Complete(0)
	_ = h.cfg.Invocations.Update(inv)
	_ = h.cfg.Publisher.Publish(events.Event{
		Topic: "chora.a2a.invocation.completed.v1",
		Payload: map[string]any{
			"invocation_id":    inv.ID,
			"agid":             inv.AGID,
			"partner_id":       inv.PartnerID,
			"capability":       inv.Capability,
			"contract_id":      grantedContract.ID,
			"contract_version": grantedContract.Version,
			"correlation_id":   inv.CorrelationID,
			"latency_ms":       inv.LatencyMS,
			"transport":        "grpc",
		},
		TenantID: tenantID, Traceparent: req.Traceparent,
		IMDADimension: "transparency", IMDALifecycleStage: "runtime",
	})
	return &InvokeResponse{
		InvocationID:    inv.ID,
		Status:          "completed",
		ContractID:      grantedContract.ID,
		ContractVersion: int32(grantedContract.Version),
		LatencyMS:       int32(inv.LatencyMS),
	}, nil
}

// GetContract returns the most-recent active contract for the partner.
func (h *Handler) GetContract(ctx context.Context, req *GetContractRequest) (*GetContractResponse, error) {
	cs, err := h.cfg.Contracts.ListByPartner(req.PartnerID)
	if err != nil {
		return nil, err
	}
	for _, c := range cs {
		if c.IsActive() {
			caps := make([]ContractCapability, 0, len(c.Capabilities))
			for _, x := range c.Capabilities {
				caps = append(caps, ContractCapability{
					Name: x.Name, Tier: string(x.Tier), RateLimitPerMin: int32(x.RateLimitPerMin),
				})
			}
			return &GetContractResponse{
				ContractID:   c.ID,
				Version:      int32(c.Version),
				AuthMethod:   string(c.AuthMethod),
				Capabilities: caps,
			}, nil
		}
	}
	return nil, errors.New("grpc: no active contract for partner")
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

var (
	errInvalidAPIKey    = errors.New("INVALID_API_KEY")
	errPartnerSuspended = errors.New("PARTNER_SUSPENDED")
)

func verifyKeyHash(reg *partner.Registration, plaintext string) bool {
	if reg.APIKeyHash == "" || plaintext == "" {
		return false
	}
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:]) == reg.APIKeyHash
}

func mustNewInvocation(reg *partner.Registration, capability, corr, traceparent string) *invocation.Invocation {
	id := newUUIDv7()
	inv, _ := invocation.New(invocation.NewParams{
		ID:            id,
		AGID:          reg.AGID,
		PartnerID:     reg.ID,
		Capability:    capability,
		CorrelationID: corr,
		Traceparent:   traceparent,
		Endpoint:      resolveDispatchEndpoint(reg, capability),
	})
	return inv
}

// resolveDispatchEndpoint mirrors the REST adapter's helper so a gRPC-routed
// invocation records the same dispatch URL as a REST-routed one. Empty
// capability yields empty endpoint (NEVER a placeholder).
func resolveDispatchEndpoint(reg *partner.Registration, capability string) string {
	cap := strings.TrimSpace(capability)
	if cap == "" {
		return ""
	}
	if reg != nil && strings.TrimSpace(reg.PartnerDomain) != "" {
		return "https://" + strings.TrimSpace(reg.PartnerDomain) + "/a2a/v1/" + cap
	}
	return "https://a2a.chora.site/a2a/invoke#" + cap
}

func newUUIDv7() string {
	return uuid.Must(uuid.NewV7()).String()
}

// _ keeps time.Now import alive (used elsewhere in the package).
var _ = time.Now
