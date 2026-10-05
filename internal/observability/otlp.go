// Package observability wires OTLP tracing for chora-a2a-gateway.
//
// Per ADR-132 §8 + Tier 3 D13 every service emits OTLP traces directly to
// the configured OTLP endpoint (OTEL_EXPORTER_OTLP_ENDPOINT — an OTel
// Collector in prod, stdout in dev) using GenAI semantic conventions. The
// legacy MiddlewareTraceparent (below) reads incoming W3C `traceparent`
// headers + logs them + echoes them on outbound responses so log
// correlation works even before the SDK init lands.
//
// Paydown II (2026-05-14, tracker #151 / C(a).S1.b follow-on) added the
// async InitAsync entry point. It delegates to commonobs.InitOTLPAsync
// so the OTel SDK wires the real OTLP exporter in its own goroutine with
// its own deadline (CHORA_OTLP_INIT_TIMEOUT_SECONDS, default 15s) and
// fail-soft semantics. The rest of bootstrap (pgx pool, event bus) gets
// the FULL bootstrap budget. Spans reach the OTLP endpoint per Tier 3 D13.
package observability

import (
	"context"
	"log"
	"net/http"
	"strings"

	"github.com/apollo-chora/chora-common/bootstrap"
	commonobs "github.com/apollo-chora/chora-common/observability"
)

const (
	headerTraceparent = "traceparent"
	headerTracestate  = "tracestate"
)

// MiddlewareTraceparent is a minimal middleware that:
//   - reads the W3C traceparent header from the inbound request, if any
//   - logs it alongside the request method/path for cross-service correlation
//   - propagates it on the response Echo header so callers can confirm
//     correlation
//
// The OTel SDK init (InitAsync) is what actually emits spans to the OTLP
// endpoint; this middleware is the log-correlation seam that pre-dates SDK
// wiring + remains useful for response-side trace echo.
func MiddlewareTraceparent(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tp := strings.TrimSpace(r.Header.Get(headerTraceparent))
		if tp != "" {
			// Echo back so the caller can verify propagation.
			w.Header().Set("X-Echoed-Traceparent", tp)
			log.Printf("trace=incoming traceparent=%s method=%s path=%s",
				tp, r.Method, r.URL.Path)
		}
		next.ServeHTTP(w, r)
	})
}

// ServiceName is the OTel service.name attribute for the gateway.
const ServiceName = "chora-a2a-gateway"

// ServiceVersion follows semver per OpenInference convention.
const ServiceVersion = "0.2.0"

// InitAsync is the fail-soft non-blocking OTLP init per C(a).S1 path (b)
// — tracker #151. Delegates to commonobs.InitOTLPAsync so OTLP init runs
// in its own goroutine with its own deadline
// (CHORA_OTLP_INIT_TIMEOUT_SECONDS, default 15s). Timeout / init-error
// degrade to a no-op shutdown so pgx pool + event bus get the FULL
// bootstrap budget.
func InitAsync(ctx context.Context) *bootstrap.OTLPHandle {
	return commonobs.InitOTLPAsync(ctx, ServiceName, ServiceVersion)
}
