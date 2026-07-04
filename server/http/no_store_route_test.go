package http

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNoStore_ScopedToAPI confirms every API response carries Cache-Control: no-store
// (even an unauthenticated 401, since the middleware runs before auth). It also proves the
// global no-store default (#433) doesn't clobber a route that deliberately sets its own,
// different Cache-Control (health's "no-cache") — that handler's later Set() on the same
// header wins over the router's earlier default.
func TestNoStore_ScopedToAPI(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	router, err := NewRouter(&config.Config{}, newTestCore(t))
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()
	client := &http.Client{}

	cacheCtl := func(path string) (int, string) {
		resp, err := client.Get(srv.URL + path)
		require.NoError(t, err)
		_ = resp.Body.Close()
		return resp.StatusCode, resp.Header.Get("Cache-Control")
	}

	// An API response (here a 401 — no auth) is no-store.
	code, cc := cacheCtl("/api/v1/secrets")
	assert.Equal(t, http.StatusUnauthorized, code)
	assert.Equal(t, "no-store", cc, "API responses must be no-store")

	// Health explicitly sets its own Cache-Control ("no-cache"), so it keeps that instead
	// of the global no-store default — a deliberate, documented exception, not a gap.
	_, cc = cacheCtl("/health")
	assert.NotEqual(t, "no-store", cc, "routes with their own explicit Cache-Control keep it")
}

// TestNoStore_GlobalDefaultCoversNonGroupedRoutes proves the router's top-level no-store
// default (#433) reaches routes registered OUTSIDE the three route groups that used to
// carry their own NoStore middleware (the pre-auth auth group, /scim/v2, /api/v1) — e.g.
// the Prometheus metrics endpoint and the OpenAPI spec — which previously had no
// Cache-Control at all and so were cacheable by default.
func TestNoStore_GlobalDefaultCoversNonGroupedRoutes(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	router, err := NewRouter(&config.Config{}, newTestCore(t))
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()
	client := &http.Client{}

	get := func(path string) string {
		resp, err := client.Get(srv.URL + path)
		require.NoError(t, err, path)
		_ = resp.Body.Close()
		return resp.Header.Get("Cache-Control")
	}

	for _, path := range []string{
		"/metrics",
		"/openapi.yaml",
	} {
		assert.Equal(t, "no-store", get(path), "%s must be no-store", path)
	}
}

// TestNoStore_StaticAssetExceptionPreserved proves the web UI's own hashed static assets
// keep their deliberate, long-lived Cache-Control (server/http/router.go's setCacheHeaders)
// rather than being clobbered by the router's global no-store default (#433). Uses a
// real on-disk asset (via WebAssetsPath) rather than a missing one — a 404 for a
// nonexistent file goes through a different, unrelated code path in net/http's
// FileServer that clears any previously-set Cache-Control regardless of this middleware.
func TestNoStore_StaticAssetExceptionPreserved(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	webDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(webDir, "assets"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(webDir, "assets", "app.js"), []byte("console.log('ok')"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(webDir, "index.html"), []byte("<html></html>"), 0o644))

	cfg := &config.Config{}
	cfg.Server.HTTP.WebAssetsPath = webDir

	router, err := NewRouter(cfg, newTestCore(t))
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/assets/app.js")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	cc := resp.Header.Get("Cache-Control")
	assert.NotEqual(t, "no-store", cc, "static assets keep their own deliberate Cache-Control")
	assert.Contains(t, cc, "max-age", "static assets keep their own deliberate Cache-Control")
}

// TestNoStore_CoversAuthAndTokenEndpoints proves the unauthenticated auth/token
// routes registered OUTSIDE the /api/v1 group (login, refresh, MFA/WebAuthn verify,
// system bootstrap, setup-link consumption, the SSO/SAML login+callback surface) also
// carry Cache-Control: no-store — now via the router's global default (#433) rather than
// a group-local one. Several of these responses mint or hand back a session token;
// without no-store a browser or intermediate cache could retain a response containing one.
func TestNoStore_CoversAuthAndTokenEndpoints(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	router, err := NewRouter(&config.Config{}, newTestCore(t))
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()
	client := &http.Client{
		// Don't follow the SSO/SAML redirects — inspect the redirect response itself.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	post := func(path string) string {
		resp, err := client.Post(srv.URL+path, "application/json", strings.NewReader("{}"))
		require.NoError(t, err, path)
		_ = resp.Body.Close()
		return resp.Header.Get("Cache-Control")
	}
	get := func(path string) string {
		resp, err := client.Get(srv.URL + path)
		require.NoError(t, err, path)
		_ = resp.Body.Close()
		return resp.Header.Get("Cache-Control")
	}

	for _, path := range []string{
		"/auth/login",
		"/auth/logout",
		"/auth/refresh",
		"/auth/password-reset",
		"/auth/mfa/verify",
		"/auth/webauthn/login/begin",
		"/auth/webauthn/login/finish",
		"/auth/webauthn/passwordless/begin",
		"/auth/webauthn/passwordless/finish",
		"/system/init",
		"/auth/setup/consume",
	} {
		assert.Equal(t, "no-store", post(path), "%s must be no-store", path)
	}

	for _, path := range []string{
		"/auth/setup/sometoken",
		"/auth/sso/providers",
		"/auth/sso/someprovider/login",
		"/auth/sso/someprovider/callback",
		"/auth/saml/someprovider/metadata",
		"/auth/saml/someprovider/login",
	} {
		assert.Equal(t, "no-store", get(path), "%s must be no-store", path)
	}
}
