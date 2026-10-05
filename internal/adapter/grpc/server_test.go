// Package grpcadapter_test exercises the gRPC InvokerServer adapter.
//
// CRITICAL invariants:
//   - Server requires a wired handler before serving (HealthCheck=SERVING)
//   - Invoke validates required fields (partner_id, capability, correlation_id)
//   - Stop is idempotent
//   - Listen rejects nil listener + duplicate calls
//   - GetContract delegates to the handler
package grpcadapter_test

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	grpcadapter "github.com/apollo-chora/chora-a2a-gateway/internal/adapter/grpc"
)

type stubHandler struct {
	calls          int
	returnError    error
	contractCalled int
}

func (s *stubHandler) Invoke(_ context.Context, _ *grpcadapter.InvokeRequest) (*grpcadapter.InvokeResponse, error) {
	s.calls++
	if s.returnError != nil {
		return nil, s.returnError
	}
	return &grpcadapter.InvokeResponse{
		InvocationID:    "01970000-0000-7000-e000-000000000001",
		Status:          "completed",
		ContractID:      "01970000-0000-7000-d000-000000000001",
		ContractVersion: 1,
		LatencyMS:       5,
	}, nil
}

func (s *stubHandler) GetContract(_ context.Context, _ *grpcadapter.GetContractRequest) (*grpcadapter.GetContractResponse, error) {
	s.contractCalled++
	return &grpcadapter.GetContractResponse{
		ContractID: "01970000-0000-7000-d000-000000000001",
		Version:    1,
		AuthMethod: "api_key",
		Capabilities: []grpcadapter.ContractCapability{
			{Name: "recommend_content", Tier: "high", RateLimitPerMin: 600},
		},
	}, nil
}

func TestInvokerServer_HealthCheck(t *testing.T) {
	t.Parallel()
	s := grpcadapter.NewInvokerServer(nil)
	if got := s.HealthCheck(); got != "NOT_SERVING" {
		t.Errorf("HealthCheck nil handler = %q; want NOT_SERVING", got)
	}
	s = grpcadapter.NewInvokerServer(&stubHandler{})
	if got := s.HealthCheck(); got != "SERVING" {
		t.Errorf("HealthCheck wired handler = %q; want SERVING", got)
	}
	_ = s.Stop()
	if got := s.HealthCheck(); got != "NOT_SERVING" {
		t.Errorf("HealthCheck after stop = %q; want NOT_SERVING", got)
	}
}

func TestInvokerServer_InvokeRequiresFields(t *testing.T) {
	t.Parallel()
	s := grpcadapter.NewInvokerServer(&stubHandler{})

	_, err := s.Invoke(context.Background(), nil)
	if err == nil {
		t.Error("expected error on nil request")
	}

	cases := []struct {
		name string
		req  *grpcadapter.InvokeRequest
	}{
		{"missing partner_id", &grpcadapter.InvokeRequest{Capability: "x", CorrelationID: "c"}},
		{"missing capability", &grpcadapter.InvokeRequest{PartnerID: "p", CorrelationID: "c"}},
		{"missing correlation_id", &grpcadapter.InvokeRequest{PartnerID: "p", Capability: "x"}},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			if _, err := s.Invoke(context.Background(), c.req); err == nil {
				t.Error("expected error")
			}
		})
	}
}

func TestInvokerServer_InvokeHappyPath(t *testing.T) {
	t.Parallel()
	h := &stubHandler{}
	s := grpcadapter.NewInvokerServer(h)
	resp, err := s.Invoke(context.Background(), &grpcadapter.InvokeRequest{
		PartnerID:     "01970000-0000-7000-a000-000000000001",
		APIKey:        "sk-test",
		Capability:    "recommend_content",
		CorrelationID: "01970000-0000-7000-c000-000000000001",
		TenantID:      "tenant-1",
	})
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if resp.Status != "completed" {
		t.Errorf("Status = %q", resp.Status)
	}
	if h.calls != 1 {
		t.Errorf("handler.calls = %d; want 1", h.calls)
	}
}

func TestInvokerServer_InvokeBubblesHandlerError(t *testing.T) {
	t.Parallel()
	h := &stubHandler{returnError: errors.New("upstream timeout")}
	s := grpcadapter.NewInvokerServer(h)
	_, err := s.Invoke(context.Background(), &grpcadapter.InvokeRequest{
		PartnerID:     "p",
		Capability:    "c",
		CorrelationID: "c",
	})
	if err == nil || !strings.Contains(err.Error(), "upstream") {
		t.Errorf("expected handler error; got %v", err)
	}
}

func TestInvokerServer_GetContract(t *testing.T) {
	t.Parallel()
	h := &stubHandler{}
	s := grpcadapter.NewInvokerServer(h)
	resp, err := s.GetContract(context.Background(), &grpcadapter.GetContractRequest{PartnerID: "p"})
	if err != nil {
		t.Fatalf("GetContract: %v", err)
	}
	if resp.ContractID == "" {
		t.Error("ContractID empty")
	}
	if h.contractCalled != 1 {
		t.Errorf("handler.contractCalled = %d", h.contractCalled)
	}
}

func TestInvokerServer_GetContractRequiresHandler(t *testing.T) {
	t.Parallel()
	s := grpcadapter.NewInvokerServer(nil)
	if _, err := s.GetContract(context.Background(), &grpcadapter.GetContractRequest{PartnerID: "p"}); err == nil {
		t.Error("expected error when handler unwired")
	}
}

func TestInvokerServer_StopIdempotent(t *testing.T) {
	t.Parallel()
	s := grpcadapter.NewInvokerServer(&stubHandler{})
	if err := s.Stop(); err != nil {
		t.Errorf("Stop 1: %v", err)
	}
	if err := s.Stop(); err != nil {
		t.Errorf("Stop 2: %v", err)
	}
}

func TestInvokerServer_ListenRejectsNilAndDup(t *testing.T) {
	t.Parallel()
	s := grpcadapter.NewInvokerServer(&stubHandler{})
	if err := s.Listen(nil); err == nil {
		t.Error("expected error on nil listener")
	}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()
	if err := s.Listen(l); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	l2, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l2.Close()
	if err := s.Listen(l2); err == nil {
		t.Error("expected error on duplicate Listen")
	}
}
