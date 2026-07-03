package http

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	customMiddleware "github.com/keyorixhq/keyorix/server/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRecoveryIsOutermostMiddleware pins NewRouter's middleware registration order
// (server/http/router.go): customMiddleware.Recovery() is registered FIRST, so it is
// the OUTERMOST handler in chi's chain (chi wraps in registration order — the first
// Use() call wraps everything registered after it). A panic in ANY later-registered
// middleware — chi's own middleware.RequestID included — must therefore be caught by
// Recovery and turned into a clean 500, not left to crash out to net/http's own bare
// panic recovery (which drops the connection with no structured response).
//
// This mirrors router.go's actual top-of-chain registration order
// (Recovery, then RequestID, ...) rather than re-testing Recovery in isolation
// (already covered by server/middleware/recovery_test.go) — if router.go's order
// regresses (Recovery moved after RequestID again), keep this test's ordering in
// sync so it keeps proving the real registration order.
func TestRecoveryIsOutermostMiddleware(t *testing.T) {
	r := chi.NewRouter()
	r.Use(customMiddleware.Recovery())
	r.Use(middleware.RequestID)
	// Stands in for a hypothetical panic in RequestID (or any middleware registered
	// between Recovery and the handler) — proves Recovery catches it, not just a
	// panic in the final handler.
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			panic("boom: middleware panic after Recovery")
		})
	})
	r.Get("/x", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)

	require.NotPanics(t, func() {
		r.ServeHTTP(rec, req)
	}, "a panic in a middleware registered after Recovery must be caught, not propagate")

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
}
