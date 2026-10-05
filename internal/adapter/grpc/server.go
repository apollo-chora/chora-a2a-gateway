// Package grpcadapter provides the chora-a2a-gateway gRPC service surface.
//
// Per Tier 1 Post-Review Addendum #1: the platform ingress routes
// `https://a2a.chora.site/*` to the gateway. The mTLS path uses gRPC over
// the service mesh; the public partner-facing path uses REST behind the
// API Gateway. This server exposes BOTH:
//
//   - the partner-facing INVOKE/CONTRACT/AUDIT methods (REST is the primary
//     external surface; gRPC is the internal A2AInvokerService surface
//     called by other Chora services to invoke external agents on behalf
//     of a learner)
//   - introspection (Health/Reflection) for service-mesh probes
//
// CRITICAL: this server does NOT depend on the chora-contracts/proto/services
// package because that lives outside this service. The gRPC layer here is a
// thin shim that embeds the same business logic (registrations, contracts,
// invocations) and exposes it over a hand-rolled gRPC service definition.
// M12 will replace the hand-rolled definition with the Protobuf-generated
// stubs from chora-contracts/proto/services/a2a/v1/a2a_invoker.proto when
// the proto package is added (per coding-protobuf skill).
package grpcadapter

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"time"
)

// InvokerServer is the gRPC server adapter. Wraps the same domain logic as
// the REST ExtRouter (partner registrations, contracts, invocations) so the
// two surfaces share state.
type InvokerServer struct {
	mu       sync.Mutex
	listener net.Listener
	stopped  bool

	// Handlers — set via WithHandlers; the server is otherwise dependency-
	// free so it can be unit-tested without spinning up a full Postgres +
	// event bus stack.
	handler InvokerHandler
}

// InvokerHandler is the port the gRPC server depends on. The production
// implementation wires the same registrations/contracts/invocations stack
// the REST adapter uses (see ext_router.go).
type InvokerHandler interface {
	// Invoke runs an external-agent capability on behalf of a Chora-side caller.
	// The handler validates contract + scope + rate-limit + records the
	// invocation just like the REST /a2a/invoke handler.
	Invoke(ctx context.Context, req *InvokeRequest) (*InvokeResponse, error)

	// GetContract returns the per-consumer contract version pinned for the
	// caller's AGID. Used by Chora-side orchestrators to know what
	// capabilities they may call on the external partner.
	GetContract(ctx context.Context, req *GetContractRequest) (*GetContractResponse, error)
}

// InvokeRequest is the input for InvokerService.Invoke.
type InvokeRequest struct {
	PartnerID     string
	APIKey        string
	Capability    string
	Params        map[string]string
	CorrelationID string
	Traceparent   string
	TenantID      string
}

// InvokeResponse is the output for InvokerService.Invoke.
type InvokeResponse struct {
	InvocationID    string
	Status          string
	ContractID      string
	ContractVersion int32
	LatencyMS       int32
	ResponseBody    map[string]string
	ErrorCode       string
}

// GetContractRequest is the input for InvokerService.GetContract.
type GetContractRequest struct {
	PartnerID string
	TenantID  string
}

// GetContractResponse is the output for InvokerService.GetContract.
type GetContractResponse struct {
	ContractID   string
	Version      int32
	AuthMethod   string
	Capabilities []ContractCapability
}

// ContractCapability mirrors contract.Capability over the wire.
type ContractCapability struct {
	Name            string
	Tier            string
	RateLimitPerMin int32
}

// NewInvokerServer constructs a new gRPC server bound to the given handler.
//
// The server purposely does NOT pull in google.golang.org/grpc as a
// dependency in the M11 skeleton (the proto stubs land in M12 — coding-protobuf
// skill); instead it exposes the InvokerServer as an opaque type that the
// cmd/server entrypoint can listen on once gRPC stubs are wired.
func NewInvokerServer(h InvokerHandler) *InvokerServer {
	return &InvokerServer{handler: h}
}

// Listen sets the TCP listener. Production wiring binds this to the gRPC
// port (default :9090) inside the service; service-mesh handles mTLS.
func (s *InvokerServer) Listen(l net.Listener) error {
	if l == nil {
		return errors.New("grpc: nil listener")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return errors.New("grpc: already listening")
	}
	s.listener = l
	return nil
}

// Stop closes the listener; subsequent calls are no-ops.
func (s *InvokerServer) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return nil
	}
	s.stopped = true
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

// HealthCheck is the gRPC Health/v1 surface analogue. Returns SERVING when
// the handler is wired and the listener is bound.
func (s *InvokerServer) HealthCheck() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handler == nil {
		return "NOT_SERVING"
	}
	if s.stopped {
		return "NOT_SERVING"
	}
	return "SERVING"
}

// Invoke is the test-friendly entrypoint that calls the underlying handler.
// In production gRPC dispatch happens via the (M12) Protobuf-generated
// service stubs; this method exists so unit tests can exercise the same
// path without a wire format.
func (s *InvokerServer) Invoke(ctx context.Context, req *InvokeRequest) (*InvokeResponse, error) {
	if req == nil {
		return nil, errors.New("grpc: nil request")
	}
	if strings.TrimSpace(req.PartnerID) == "" {
		return nil, errors.New("grpc: partner_id required")
	}
	if strings.TrimSpace(req.Capability) == "" {
		return nil, errors.New("grpc: capability required")
	}
	if strings.TrimSpace(req.CorrelationID) == "" {
		return nil, errors.New("grpc: correlation_id required (idempotency)")
	}
	if s.handler == nil {
		return nil, errors.New("grpc: handler not wired")
	}
	// Wrap with a request timeout if the caller didn't set one.
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
	}
	return s.handler.Invoke(ctx, req)
}

// GetContract is the test-friendly contract introspection entrypoint.
func (s *InvokerServer) GetContract(ctx context.Context, req *GetContractRequest) (*GetContractResponse, error) {
	if req == nil {
		return nil, errors.New("grpc: nil request")
	}
	if strings.TrimSpace(req.PartnerID) == "" {
		return nil, errors.New("grpc: partner_id required")
	}
	if s.handler == nil {
		return nil, errors.New("grpc: handler not wired")
	}
	return s.handler.GetContract(ctx, req)
}
