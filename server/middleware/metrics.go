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
		method := normalizeMethod(r.Method)
		httpRequestsTotal.WithLabelValues(method, route, strconv.Itoa(status)).Inc()
		httpRequestDuration.WithLabelValues(method, route).Observe(time.Since(start).Seconds())
	})
}

// knownMethods bounds the `method` metric label. net/http accepts any RFC-7230 token
// as a request method, so labelling series with the raw method would let an
// unauthenticated caller spawn unbounded time series (one per distinct method, ×buckets
// in the histogram) and exhaust the registry — a memory-exhaustion DoS. Anything outside
// this allow-list collapses to "other".
var knownMethods = map[string]bool{
	http.MethodGet: true, http.MethodPost: true, http.MethodPut: true, http.MethodPatch: true,
	http.MethodDelete: true, http.MethodHead: true, http.MethodOptions: true,
	http.MethodConnect: true, http.MethodTrace: true,
}

func normalizeMethod(m string) string {
	if knownMethods[m] {
		return m
	}
	return "other"
}

// MetricsHandler serves the Prometheus exposition endpoint (default registry:
// the custom HTTP metrics above plus Go runtime + process collectors).
func MetricsHandler() http.Handler {
	return promhttp.Handler()
}
