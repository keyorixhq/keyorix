// metrics.go — Prometheus instrumentation.
//
// PrometheusMiddleware records per-request count and latency, labelled by the chi
// route pattern (e.g. "/api/v1/secrets/{id}") rather than the raw path, so
// cardinality stays bounded. MetricsHandler serves the exposition endpoint, which
// also carries the Go runtime + process collectors registered on the default
// registry. The endpoint is unauthenticated by design (standard for Prometheus
// scraping) — keep it inside your perimeter; do not expose it publicly.
package middleware

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	httpRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "keyorix_http_requests_total",
		Help: "Total HTTP requests, by method, matched route, and status code.",
	}, []string{"method", "route", "status"})

	httpRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "keyorix_http_request_duration_seconds",
		Help:    "HTTP request latency in seconds, by method and matched route.",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "route"})
)

// PrometheusMiddleware records request count and latency for every request.
func PrometheusMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := chimw.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)

		// RoutePattern is populated once chi has matched the route, so it is read
		// after the handler runs. Unmatched requests (404s) share one label to
		// avoid unbounded cardinality from arbitrary paths.
		route := chi.RouteContext(r.Context()).RoutePattern()
		if route == "" {
			route = "unmatched"
		}
		status := ww.Status()
		if status == 0 {
			status = http.StatusOK // handler returned without an explicit WriteHeader
		}
		httpRequestsTotal.WithLabelValues(r.Method, route, strconv.Itoa(status)).Inc()
		httpRequestDuration.WithLabelValues(r.Method, route).Observe(time.Since(start).Seconds())
	})
}

// MetricsHandler serves the Prometheus exposition endpoint (default registry:
// the custom HTTP metrics above plus Go runtime + process collectors).
func MetricsHandler() http.Handler {
	return promhttp.Handler()
}
