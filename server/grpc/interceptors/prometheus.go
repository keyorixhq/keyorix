// prometheus.go — bridges the in-memory gRPC metrics (atomic counters in
// metrics.go) into the default Prometheus registry, so gRPC request volume,
// outcomes, and latency are scrapable from the same /metrics endpoint as the HTTP
// metrics. Without this, gRPC observability was reachable only via an
// authenticated SystemService.GetMetrics RPC — not Prometheus time series.
package interceptors

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// grpcCollector reports the gRPC counters on each scrape (read live from the
// atomics), so it never drifts from the interceptor's view and adds no per-request
// cost. Counters are monotonic, matching Prometheus' counter semantics.
type grpcCollector struct {
	requests *prometheus.Desc
	duration *prometheus.Desc
}

func newGRPCCollector() *grpcCollector {
	return &grpcCollector{
		requests: prometheus.NewDesc(
			"keyorix_grpc_requests_total",
			"Total gRPC unary requests, by outcome (success or error).",
			[]string{"status"}, nil,
		),
		duration: prometheus.NewDesc(
			"keyorix_grpc_request_duration_seconds_total",
			"Cumulative gRPC unary handler time in seconds; divide its rate by the request rate for average latency.",
			nil, nil,
		),
	}
}

func (c *grpcCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.requests
	ch <- c.duration
}

func (c *grpcCollector) Collect(ch chan<- prometheus.Metric) {
	m := GetGRPCMetrics()
	ch <- prometheus.MustNewConstMetric(c.requests, prometheus.CounterValue, float64(m.SuccessRequests), "success")
	ch <- prometheus.MustNewConstMetric(c.requests, prometheus.CounterValue, float64(m.ErrorRequests), "error")
	ch <- prometheus.MustNewConstMetric(c.duration, prometheus.CounterValue, float64(m.TotalDuration)/1e9)
}

var registerOnce sync.Once

// RegisterPrometheusMetrics registers the gRPC metrics collector on the default
// Prometheus registry (the one promhttp.Handler serves at /metrics). Safe to call
// more than once.
func RegisterPrometheusMetrics() {
	registerOnce.Do(func() {
		prometheus.MustRegister(newGRPCCollector())
	})
}
