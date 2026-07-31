package http

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newOnDiskWebUIRouter builds a router serving a temp on-disk web build with an
// /assets directory that has NO index.html inside it — mirroring the real SPA
// build's layout (dist/assets has no index) — so directory-listing behavior is
// directly testable, unlike the embedded placeholder build used elsewhere.
func newOnDiskWebUIRouter(t *testing.T) *httptest.Server {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "index.html"), []byte("<html>Keyorix</html>"), 0644))
	require.NoError(t, os.Mkdir(filepath.Join(dir, "assets"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "assets", "app.js"), []byte("console.log(1)"), 0644))

	cfg := &config.Config{}
	cfg.Server.HTTP.WebAssetsPath = dir
	router, err := NewRouter(cfg, newTestCore(t))
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	return srv
}

// TestAssetDirListing_Returns404NotListing pins #213: a directory-resolving
// request under /assets/ (no index.html inside it) must 404, not fall through to
// Go's default http.FileServer directory listing of every bundled filename.
func TestAssetDirListing_Returns404NotListing(t *testing.T) {
	srv := newOnDiskWebUIRouter(t)
	client := &http.Client{}

	// "/assets" (no trailing slash) doesn't match the "/assets/*" wildcard route at
	// all in chi — it falls straight to the SPA fallback like any other client
	// route, never reaching http.FileServer, so it is not a listing vector and is
	// intentionally not asserted here; "/assets/" is the actual listing case.
	resp, err := client.Get(srv.URL + "/assets/")
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "GET /assets/ must be 404, not a directory listing")

	// A real asset file inside the directory must still be served normally.
	resp, err = client.Get(srv.URL + "/assets/app.js")
	require.NoError(t, err)
	body := readAll(t, resp.Body)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "console.log(1)", body)
}

// TestOpenAPISpec_GatedBySwaggerEnabled pins #224: /openapi.yaml was previously
// registered unconditionally, so disabling swagger_enabled still left the
// machine-readable OpenAPI spec (internal API surface, parameter names,
// structure) exposed even though the human-facing /swagger/ UI was correctly
// gated behind the same toggle. Both routes must share identical on/off
// behavior.
func TestOpenAPISpec_GatedBySwaggerEnabled(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	newRouterWithSwagger := func(t *testing.T, enabled bool) *httptest.Server {
		t.Helper()
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "index.html"), []byte("<html>Keyorix</html>"), 0644))

		cfg := &config.Config{}
		cfg.Server.HTTP.WebAssetsPath = dir
		cfg.Server.HTTP.SwaggerEnabled = enabled
		router, err := NewRouter(cfg, newTestCore(t))
		require.NoError(t, err)
		srv := httptest.NewServer(router)
		t.Cleanup(srv.Close)
		return srv
	}

	t.Run("disabled: both swagger UI and openapi.yaml 404", func(t *testing.T) {
		srv := newRouterWithSwagger(t, false)
		client := &http.Client{}

		resp, err := client.Get(srv.URL + "/openapi.yaml")
		require.NoError(t, err)
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode, "GET /openapi.yaml must 404 when swagger_enabled is false")

		resp, err = client.Get(srv.URL + "/swagger/")
		require.NoError(t, err)
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode, "GET /swagger/ must 404 when swagger_enabled is false")
	})

	t.Run("enabled: both swagger UI and openapi.yaml serve", func(t *testing.T) {
		srv := newRouterWithSwagger(t, true)
		client := &http.Client{}

		resp, err := client.Get(srv.URL + "/openapi.yaml")
		require.NoError(t, err)
		body := readAll(t, resp.Body)
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode, "GET /openapi.yaml must serve when swagger_enabled is true")
		assert.NotEmpty(t, body)

		resp, err = client.Get(srv.URL + "/swagger/")
		require.NoError(t, err)
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode, "GET /swagger/ must serve when swagger_enabled is true")
	})
}

// TestNotFound_BackendRoutePrefixesReturn404 pins #214: an unmatched path under a
// KNOWN backend route family (not just /api/) must 404, not silently fall through
// to the SPA shell with a 200.
func TestNotFound_BackendRoutePrefixesReturn404(t *testing.T) {
	srv := newOnDiskWebUIRouter(t)
	client := &http.Client{}

	for _, p := range []string{
		"/auth/does-not-exist",
		"/scim/v2/does-not-exist",
		"/system/init/typo",
		"/health/nested/typo",
		"/readyz/typo",
		"/metrics/typo",
		"/status/typo",
		"/swagger/typo",
		"/openapi.yaml.bak",
		// Bare paths without trailing slash — ZAP/100001: these must also 404 rather
		// than fall through to the SPA and return HTML (DAST #1210).
		"/api",
		"/auth",
		"/scim",
		"/swagger",
		// /api/v1/does-not-exist is NOT asserted here: an unmatched path inside the
		// /api/v1 subrouter never reaches this NotFound handler at all — it's caught
		// by the subrouter's own auth middleware first (401, see
		// TestStaticAssets_RejectMutatingMethods) — so /api/ coverage here would be
		// redundant with, not additive to, this handler's own prefix check.
	} {
		resp, err := client.Get(srv.URL + p)
		require.NoError(t, err)
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode, "GET %s must be 404, not the SPA shell", p)
	}

	// An unmatched path OUTSIDE every known backend family is still a client-side
	// SPA route and must resolve to index.html (unchanged behavior).
	resp, err := client.Get(srv.URL + "/admin/users")
	require.NoError(t, err)
	body := readAll(t, resp.Body)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, body, "Keyorix")
}

// TestNotFound_NonHTMLAcceptReturnsJSON404 pins #1245 (ZAP/100001, "Unexpected
// Content-Type was returned"): a fuzzed/mistyped path that doesn't exactly
// prefix-match a known backend route family still falls through to this
// NotFound handler, and previously always served the SPA shell's text/html —
// including to a scanner or API client that explicitly asked for JSON and
// never accepted HTML. The handler must honor Accept and return a JSON 404 for
// those callers, while browsers (which always send text/html or */* in
// Accept, or send no Accept header at all) keep getting the SPA shell.
func TestNotFound_NonHTMLAcceptReturnsJSON404(t *testing.T) {
	srv := newOnDiskWebUIRouter(t)
	client := &http.Client{}

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/does-not-exist-and-not-a-prefix-match", nil)
	require.NoError(t, err)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	require.NoError(t, err)
	body := readAll(t, resp.Body)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get(hdrContentType))
	assert.NotContains(t, body, "<html", "a JSON-Accept client must never receive the SPA shell")

	// A browser-style Accept header still gets the SPA shell (unchanged behavior).
	req, err = http.NewRequest(http.MethodGet, srv.URL+"/admin/users", nil)
	require.NoError(t, err)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	resp, err = client.Do(req)
	require.NoError(t, err)
	body = readAll(t, resp.Body)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, body, "Keyorix")
}
