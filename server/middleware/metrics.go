// metrics.go — Prometheus instrumentation.
//
// PrometheusMiddleware records per-request count and latency, labelled by the chi
// route pattern (e.g. "/api/v1/secrets/{id}") rather than the raw path, so
// cardinality stays bounded. MetricsHandler serves the exposition endpoint, which
// also carries the Go runtime + process collectors registered on the default
// registry — minus suppressedMetricFamilies, a couple of default collector metrics
// (exact Go version, process start time) that are minor recon information and add
// no monitoring value the endpoint's other metrics don't already cover. The endpoint
// is unauthenticated by design (standard for Prometheus scraping) — keep it inside
// your perimeter; do not expose it publicly.
package middleware

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	dto "github.com/prometheus/client_model/go"

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

		// #G55: previously the metric-recording logic below ran only on normal
		// return — a panicking handler skipped straight past it (this function's own
		// stack frame unwinds without ever reaching the code after next.ServeHTTP),
		// making panicking requests invisible in metrics entirely. A defer runs
		// regardless of panic vs. normal return; recover()+re-panic here records the
		// request (as the 500 Recovery, further up the chain, will produce) without
		// swallowing the panic — Recovery still needs to see it to respond.
		defer func() {
			// RoutePattern is populated once chi has matched the route, so it is read
			// after the handler runs. Unmatched requests (404s) share one label to
			// avoid unbounded cardinality from arbitrary paths.
			route := chi.RouteContext(r.Context()).RoutePattern()
			if route == "" {
				route = "unmatched"
			}
			panicVal := recover()
			var status int
			switch {
			case panicVal != nil:
				// ww.Status() is still 0 here — nothing has been written through ww at
				// this point in the panic unwind (Recovery's own write happens later,
				// further up the stack). Record the status Recovery will actually send.
				status = http.StatusInternalServerError
			case ww.Status() == 0:
				status = http.StatusOK // handler returned without an explicit WriteHeader
			default:
				status = ww.Status()
			}
			method := normalizeMethod(r.Method)
			httpRequestsTotal.WithLabelValues(method, route, strconv.Itoa(status)).Inc()
			httpRequestDuration.WithLabelValues(method, route).Observe(time.Since(start).Seconds())
			if panicVal != nil {
				panic(panicVal)
			}
		}()

		next.ServeHTTP(ww, r)
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

// suppressedMetricFamilies are default Go-runtime/process metric families dropped
// from the exposition endpoint: they disclose minor recon information (exact Go
// version, process start time / uptime) to anyone who can reach /metrics, which is
// unauthenticated by design (see the package doc above). Every other Go runtime and
// process collector metric (goroutines, memstats, GC, threads, open fds, cpu
// seconds, resident memory, …) stays exposed — those are useful for legitimate
// monitoring and don't identify the exact binary version or process age.
var suppressedMetricFamilies = map[string]bool{
	"go_info":                    true, // exact Go compiler/runtime version
	"process_start_time_seconds": true, // exact process start time (derives uptime)
}

// filteringGatherer wraps a prometheus.Gatherer and drops metric families named in
// drop before they are ever serialized to a scrape response.
type filteringGatherer struct {
	inner prometheus.Gatherer
	drop  map[string]bool
}

func (f filteringGatherer) Gather() ([]*dto.MetricFamily, error) {
	mfs, err := f.inner.Gather()
	if err != nil {
		return nil, err
	}
	out := make([]*dto.MetricFamily, 0, len(mfs))
	for _, mf := range mfs {
		if f.drop[mf.GetName()] {
			continue
		}
		out = append(out, mf)
	}
	return out, nil
}

// MetricsHandler serves the Prometheus exposition endpoint (default registry: the
// custom HTTP metrics above plus Go runtime + process collectors), with
// suppressedMetricFamilies filtered out.
func MetricsHandler() http.Handler {
	g := filteringGatherer{inner: prometheus.DefaultGatherer, drop: suppressedMetricFamilies}
	return promhttp.HandlerFor(g, promhttp.HandlerOpts{})
}
