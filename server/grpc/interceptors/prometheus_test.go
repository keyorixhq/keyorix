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

// RegisterPrometheusMetrics is safe to call repeatedly (it would otherwise panic on
// a duplicate registration).
func TestRegisterPrometheusMetricsIdempotent(t *testing.T) {
	require.NotPanics(t, func() {
		RegisterPrometheusMetrics()
		RegisterPrometheusMetrics()
	})
}
