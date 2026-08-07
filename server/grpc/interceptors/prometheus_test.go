package interceptors

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

// The collector reports gRPC request outcomes as Prometheus counters, driven by the
// same atomics the MetricsInterceptor increments.
func TestGRPCPrometheusCollector(t *testing.T) {
	// Reset the package-global counters for a deterministic comparison.
	atomic.StoreInt64(&grpcMetrics.TotalRequests, 0)
	atomic.StoreInt64(&grpcMetrics.SuccessRequests, 0)
	atomic.StoreInt64(&grpcMetrics.ErrorRequests, 0)
	atomic.StoreInt64(&grpcMetrics.TotalDuration, 0)

	intercept := MetricsInterceptor()
	info := &grpc.UnaryServerInfo{FullMethod: "/keyorix.SecretService/Get"}
	ok := func(context.Context, interface{}) (interface{}, error) { return "ok", nil }
	fail := func(context.Context, interface{}) (interface{}, error) { return nil, errors.New("boom") }

	_, _ = intercept(context.Background(), nil, info, ok)
	_, _ = intercept(context.Background(), nil, info, ok)
	_, _ = intercept(context.Background(), nil, info, fail)

	reg := prometheus.NewRegistry()
	reg.MustRegister(newGRPCCollector())

	expected := `
# HELP keyorix_grpc_requests_total Total gRPC unary requests, by outcome (success or error).
# TYPE keyorix_grpc_requests_total counter
keyorix_grpc_requests_total{status="error"} 1
keyorix_grpc_requests_total{status="success"} 2
`
	// Filter to the deterministic counter (duration depends on wall-clock).
	require.NoError(t, testutil.GatherAndCompare(reg, strings.NewReader(expected), "keyorix_grpc_requests_total"))
}

// The cumulative-duration counter converts the atomic's nanoseconds to seconds
// (dividing by 1e9), matching Prometheus' convention for a *_seconds metric.
// Deliberately drives TotalDuration directly rather than through the
// interceptor's real wall-clock timing (as TestGRPCPrometheusCollector above
// does for the other two counters) so the expected value is exact, not just
// "some positive number" -- an ARITHMETIC_BASE mutant turning /1e9 into
// *1e9 or +1e9 previously survived because no test asserted this counter's
// value at all.
func TestGRPCPrometheusCollector_DurationConvertsNanosecondsToSeconds(t *testing.T) {
	atomic.StoreInt64(&grpcMetrics.TotalRequests, 0)
	atomic.StoreInt64(&grpcMetrics.SuccessRequests, 0)
	atomic.StoreInt64(&grpcMetrics.ErrorRequests, 0)
	atomic.StoreInt64(&grpcMetrics.TotalDuration, 5_000_000_000) // exactly 5s in ns

	reg := prometheus.NewRegistry()
	reg.MustRegister(newGRPCCollector())

	expected := `
# HELP keyorix_grpc_request_duration_seconds_total Cumulative gRPC unary handler time in seconds; divide its rate by the request rate for average latency.
# TYPE keyorix_grpc_request_duration_seconds_total counter
keyorix_grpc_request_duration_seconds_total 5
`
	require.NoError(t, testutil.GatherAndCompare(reg, strings.NewReader(expected), "keyorix_grpc_request_duration_seconds_total"))
}

// RegisterPrometheusMetrics is safe to call repeatedly (it would otherwise panic on
// a duplicate registration).
func TestRegisterPrometheusMetricsIdempotent(t *testing.T) {
	require.NotPanics(t, func() {
		RegisterPrometheusMetrics()
		RegisterPrometheusMetrics()
	})
}
