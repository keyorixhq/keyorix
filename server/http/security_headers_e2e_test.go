package http

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
)

// assertBaselineSecurityHeaders checks the hardening headers SecurityHeaders()
// (server/middleware/security_headers.go) sets unconditionally on EVERY response,
// regardless of route, auth state, or status code. HSTS (TLS-gated) and
// Cache-Control (route-specific policy, already covered end-to-end by
// no_store_route_test.go) are asserted separately by each call site instead of
// here, since their expected value legitimately differs by route.
func assertBaselineSecurityHeaders(t *testing.T, resp *http.Response, where string) {
	t.Helper()
	h := resp.Header
	assert.Equal(t, "nosniff", h.Get("X-Content-Type-Options"), "%s: X-Content-Type-Options", where)
	assert.Equal(t, "DENY", h.Get("X-Frame-Options"), "%s: X-Frame-Options", where)
	assert.Equal(t, "no-referrer", h.Get("Referrer-Policy"), "%s: Referrer-Policy", where)
	assert.Equal(t, "same-origin", h.Get("Cross-Origin-Resource-Policy"), "%s: Cross-Origin-Resource-Policy", where)
	assert.Equal(t, "require-corp", h.Get("Cross-Origin-Embedder-Policy"), "%s: Cross-Origin-Embedder-Policy", where)
	assert.Equal(t, "same-origin", h.Get("Cross-Origin-Opener-Policy"), "%s: Cross-Origin-Opener-Policy", where)
	assert.Equal(t, "none", h.Get("X-Permitted-Cross-Domain-Policies"), "%s: X-Permitted-Cross-Domain-Policies", where)
	assert.NotEmpty(t, h.Get("Permissions-Policy"), "%s: Permissions-Policy", where)
	csp := h.Get("Content-Security-Policy")
	assert.Contains(t, csp, "frame-ancestors 'none'", "%s: Content-Security-Policy frame-ancestors", where)
	assert.Contains(t, csp, "script-src 'self'", "%s: Content-Security-Policy script-src", where)
}

// TestSecurityHeaders_RealRouter is the end-to-end counterpart to
// server/middleware/security_headers_test.go: that test proves SecurityHeaders()
// sets the right headers on a synthetic handler wrapped in isolation, never
// through chi -- it does not prove the middleware is actually reachable on real
// webui/API routes through the production router (server/http/router.go's
// NewRouter + registerWebUI). This test boots the real router (as
// embedded_webui_test.go does) and asserts the headers on the SPA shell, a
// static asset, an authenticated API route, a 404, and an error (panic-recovered
// 500) response -- five response paths through the actual middleware chain.
func TestSecurityHeaders_RealRouter(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	webDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(webDir, "index.html"), []byte("<html>Keyorix</html>"), 0o644))
	require.NoError(t, os.Mkdir(filepath.Join(webDir, "assets"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(webDir, "assets", "app.js"), []byte("console.log(1)"), 0o644))

	cfg := &config.Config{}
	cfg.Server.HTTP.WebAssetsPath = webDir

	testCore := newTestCore(t)
	router, err := NewRouter(cfg, testCore)
	require.NoError(t, err)

	// Mount a test-only route onto the SAME chi.Mux NewRouter built, after
	// NewRouter's own route registration -- it goes through the exact same
	// middleware chain (Recovery, SecurityHeaders, NoStore, ...) as every real
	// route, without touching router.go. This proves SecurityHeaders' doc-comment
	// claim that headers are set "before the handler runs... including... panics"
	// on an actual error response, not just on a happy-path one.
	cr, ok := router.(chi.Router)
	require.True(t, ok, "NewRouter must return a chi.Router to mount the test-only panic route")
	cr.Get("/__test/panic", func(http.ResponseWriter, *http.Request) {
		panic("boom: security-headers-e2e-test")
	})

	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	client := &http.Client{}
	token := createTestToken(t, testCore)

	t.Run("SPA index", func(t *testing.T) {
		resp, err := client.Get(srv.URL + "/")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		assertBaselineSecurityHeaders(t, resp, "SPA index")
	})

	t.Run("static asset", func(t *testing.T) {
		resp, err := client.Get(srv.URL + "/assets/app.js")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		assertBaselineSecurityHeaders(t, resp, "static asset")
	})

	t.Run("authenticated API route", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/auth/profile", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		assertBaselineSecurityHeaders(t, resp, "authenticated API route")
		assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"), "authenticated API route: Cache-Control")
	})

	t.Run("404", func(t *testing.T) {
		// "/auth/does-not-exist" is a known backend route family (see
		// static_hardening_test.go's TestNotFound_BackendRoutePrefixesReturn404),
		// so it reaches the real NotFound handler and 404s rather than falling
		// through to the SPA shell -- unlike an unmatched /api/v1/* path, which
		// never reaches NotFound at all (caught by that group's own auth
		// middleware first, per that same test's comment).
		resp, err := client.Get(srv.URL + "/auth/does-not-exist")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusNotFound, resp.StatusCode)
		assertBaselineSecurityHeaders(t, resp, "404")
	})

	t.Run("error response (panic recovered)", func(t *testing.T) {
		resp, err := client.Get(srv.URL + "/__test/panic")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusInternalServerError, resp.StatusCode)
		assertBaselineSecurityHeaders(t, resp, "error response")
	})
}

// TestSecurityHeaders_HSTS_GatedByTLSEnabled proves HSTS is sent only when the
// process itself terminates TLS (cfg.Server.HTTP.TLS.Enabled), per
// SecurityHeaders' doc comment -- sending it over plain HTTP would tell a
// browser to force HTTPS for a host that isn't serving it.
func TestSecurityHeaders_HSTS_GatedByTLSEnabled(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	newRouter := func(t *testing.T, tlsEnabled bool) *httptest.Server {
		t.Helper()
		cfg := &config.Config{}
		cfg.Server.HTTP.TLS.Enabled = tlsEnabled
		router, err := NewRouter(cfg, newTestCore(t))
		require.NoError(t, err)
		srv := httptest.NewServer(router)
		t.Cleanup(srv.Close)
		return srv
	}

	t.Run("TLS disabled: no HSTS", func(t *testing.T) {
		srv := newRouter(t, false)
		resp, err := http.Get(srv.URL + "/health")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		assert.Empty(t, resp.Header.Get("Strict-Transport-Security"))
	})

	t.Run("TLS enabled: HSTS present", func(t *testing.T) {
		srv := newRouter(t, true)
		resp, err := http.Get(srv.URL + "/health")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		assert.NotEmpty(t, resp.Header.Get("Strict-Transport-Security"))
	})
}
