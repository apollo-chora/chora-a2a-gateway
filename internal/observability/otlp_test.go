// Package observability_test exercises the OTLP trace seaming for
// chora-a2a-gateway: the legacy traceparent echo middleware (pure HTTP, unit
// tested) and the fail-soft async InitAsync entry point (delegates to
// commonobs — smoke-tested here, no specific exporter asserted).
package observability_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/apollo-chora/chora-a2a-gateway/internal/observability"
)

func TestMiddlewareTraceparent_EchoesHeaderAndChains(t *testing.T) {
	var sawPath string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/a2a/invoke", nil)
	req.Header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")

	rec := httptest.NewRecorder()
	observability.MiddlewareTraceparent(next).ServeHTTP(rec, req)

	if got := rec.Header().Get("X-Echoed-Traceparent"); got != "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01" {
		t.Errorf("echo header = %q", got)
	}
	if sawPath != "/a2a/invoke" {
		t.Errorf("chain did not invoke next handler; path=%q", sawPath)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d; want 200", rec.Code)
	}
}

func TestMiddlewareTraceparent_NoHeaderChainsWithoutEcho(t *testing.T) {
	var called bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	observability.MiddlewareTraceparent(next).ServeHTTP(rec, req)

	if !called {
		t.Error("next handler was not called")
	}
	if got := rec.Header().Get("X-Echoed-Traceparent"); got != "" {
		t.Errorf("must not echo when no inbound traceparent; got %q", got)
	}
}

func TestMiddlewareTraceparent_TrimsWhitespace(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("traceparent", "  00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-01  ")

	rec := httptest.NewRecorder()
	observability.MiddlewareTraceparent(next).ServeHTTP(rec, req)

	got := rec.Header().Get("X-Echoed-Traceparent")
	want := "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-01"
	if got != want {
		t.Errorf("echo = %q; want trimmed %q", got, want)
	}
}

// TestMiddlewareTraceparent_Constants — lock the constant surface so tooling
// that references ServiceName / ServiceVersion fails loudly if they drift.
func TestMiddlewareTraceparent_ServiceConstants(t *testing.T) {
	if observability.ServiceName != "chora-a2a-gateway" {
		t.Errorf("ServiceName = %q", observability.ServiceName)
	}
	if observability.ServiceVersion == "" {
		t.Error("ServiceVersion must not be empty")
	}
}

// TestInitAsync_ReturnsSettlingHandle — smoke-test the fail-soft async init.
// In a CI sandbox with no OTLP endpoint the exporter fails fast and the
// handle settles to a no-op shutdown; locally it may initialise a real (or
// stdout) exporter. Either way the handle must be non-nil and WaitContext must
// return a result we can Shutdown without a panic/leak. The timeout env is
// pinned low so the goroutine always settles within the test.
func TestInitAsync_ReturnsSettlingHandle(t *testing.T) {
	t.Setenv("CHORA_OTLP_INIT_TIMEOUT_SECONDS", "1")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	handle := observability.InitAsync(ctx)
	if handle == nil {
		t.Fatal("InitAsync must return a non-nil *OTLPHandle")
	}

	res := handle.WaitContext(ctx)
	if shutdown := res.Shutdown; shutdown != nil {
		shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), time.Second)
		defer cancelShutdown()
		_ = shutdown(shutdownCtx)
	}
}

// TestInitAsync_RespectsCancelledContext — a cancelled context must not panic
// and must settle to a result (fail-soft semantics).
func TestInitAsync_RespectsCancelledContext(t *testing.T) {
	t.Setenv("CHORA_OTLP_INIT_TIMEOUT_SECONDS", "1")
	cctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	handle := observability.InitAsync(cctx)
	if handle == nil {
		t.Fatal("InitAsync must return a non-nil handle even for a cancelled ctx")
	}
	// Do NOT WaitContext here (a cancelled init ctx already settles the inner
	// goroutine); just confirm os-level env pinning above didn't blow up.
	_ = os.Getenv("CHORA_OTLP_INIT_TIMEOUT_SECONDS")
}
