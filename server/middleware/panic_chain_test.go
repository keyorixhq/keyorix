// panic_chain_test.go — #G55 detection_idea: a handler that writes a PARTIAL
// response then panics, run through the REAL middleware chain order (Recovery
// outermost, then Logger, then PrometheusMiddleware innermost — see router.go's
// r.Use registration order). Asserts all three of the group's own acceptance
// criteria at once: the client sees a clean abort (not corrupted/duplicated
// output), the Prometheus counter for that request still increments, and the
// access log records status 500 (not a misleading 0).
package middleware

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// chainedRecoveryLoggerMetrics reproduces router.go's real registration order:
// Recovery(Logger(PrometheusMiddleware(next))).
func chainedRecoveryLoggerMetrics(next http.Handler) http.Handler {
	return Recovery()(Logger()(PrometheusMiddleware(next)))
}

func TestPanicChain_PartialWriteThenPanic(t *testing.T) {
	const partialBody = "partial-body-before-panic"
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(partialBody))
		panic("boom mid-response")
	})

	var logBuf bytes.Buffer
	origOut := log.Writer()
	log.SetOutput(&logBuf)
	defer log.SetOutput(origOut)

	before := testutil.ToFloat64(httpRequestsTotal.WithLabelValues(http.MethodGet, "unmatched", "500"))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/panics-midway", nil)

	// Recovery's own defer re-panics with http.ErrAbortHandler once it sees a
	// response was already started (ww.Status() != 0) — the client-facing
	// consequence of a genuinely mid-response panic is an aborted connection, which
	// httptest.ResponseRecorder can't simulate directly, so the test observes it as
	// this panic propagating out of ServeHTTP (matching what a real net/http.Server
	// does: abort the connection, no further write, no stack-trace log for this
	// specific sentinel).
	func() {
		defer func() {
			r := recover()
			require.NotNil(t, r, "a mid-response panic must propagate out as http.ErrAbortHandler, not be silently swallowed")
			assert.Equal(t, http.ErrAbortHandler, r)
		}()
		chainedRecoveryLoggerMetrics(handler).ServeHTTP(rec, req)
	}()

	// Client sees exactly what the handler itself wrote — no corrupted/duplicated
	// JSON-500 payload appended after the partial body.
	assert.Equal(t, http.StatusOK, rec.Code, "the status the handler already sent must be untouched")
	assert.Equal(t, partialBody, rec.Body.String(), "no additional content may be appended after a mid-response panic")

	// The Prometheus counter for this (method, route, 500) combination still
	// incremented — a panicking request is not invisible in metrics, even though
	// the client-visible status code was never actually 500 in this exact edge case
	// (the handler already committed 200) — 500 is what Recovery WOULD have sent had
	// the response not already started, and is what the request's outcome was.
	after := testutil.ToFloat64(httpRequestsTotal.WithLabelValues(http.MethodGet, "unmatched", "500"))
	assert.Equal(t, before+1, after, "the panicking request must still be recorded in metrics")

	// The access log recorded status 500, not a misleading 0.
	assert.Contains(t, logBuf.String(), " 500 ", "the access log must record the eventual 500, not a misleading 0")
}

// TestPanicChain_PanicBeforeAnyWrite is the more common case: the handler panics
// before writing anything. Recovery can (and must) still produce a clean JSON 500,
// and metrics/logging must record it accurately — this is the sibling case to the
// partial-write one above, confirming the fix didn't regress the common path.
func TestPanicChain_PanicBeforeAnyWrite(t *testing.T) {
	handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom before any write")
	})

	var logBuf bytes.Buffer
	origOut := log.Writer()
	log.SetOutput(&logBuf)
	defer log.SetOutput(origOut)

	before := testutil.ToFloat64(httpRequestsTotal.WithLabelValues(http.MethodGet, "unmatched", "500"))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/panics-immediately", nil)
	chainedRecoveryLoggerMetrics(handler).ServeHTTP(rec, req)

	require.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	after := testutil.ToFloat64(httpRequestsTotal.WithLabelValues(http.MethodGet, "unmatched", "500"))
	assert.Equal(t, before+1, after, "the panicking request must be recorded in metrics")

	assert.Contains(t, logBuf.String(), " 500 ", "the access log must record status 500")
}
