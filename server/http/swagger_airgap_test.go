package http

import (
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// AIRGAP-WEBUI-1 item 2, through the production router: /swagger/ and every
// subresource it names are same-origin, served (not shadowed by the SPA fallback),
// and loadable under the CSP the router actually sends. The header policy itself
// is not asserted here beyond what the page needs (HARDEN-HTTP-1 owns it).
//
// Not covered: a real browser executing the bundle; this checks the contract the
// browser enforces (script-src 'self', same-origin references), not the rendering.
func TestSwaggerUIThroughRouter_NoExternalHostUnderCSP(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	cfg := &config.Config{}
	cfg.Server.HTTP.SwaggerEnabled = true
	router, err := NewRouter(cfg, core.NewKeyorixCore(store.NewLocalStorage(db)))
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()

	get := func(p string) (*http.Response, string) {
		resp, err := http.Get(srv.URL + p)
		require.NoError(t, err, p)
		defer func() { _ = resp.Body.Close() }()
		b, err := io.ReadAll(resp.Body)
		require.NoError(t, err, p)
		return resp, string(b)
	}

	resp, page := get("/swagger/")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	csp := resp.Header.Get("Content-Security-Policy")
	require.Contains(t, csp, "script-src 'self';", "page must be judged under a script-src without 'unsafe-inline'")

	assert.NotRegexp(t, `(?i)https?://`, page, "swagger page names an external origin")
	assert.NotRegexp(t, `(?i)<script(?:\s[^>]*)?>\s*[^<\s]`, page, "inline script is blocked by the CSP")

	refs := regexp.MustCompile(`(?:src|href)="([^"]+)"`).FindAllStringSubmatch(page, -1)
	require.NotEmpty(t, refs)
	for _, m := range refs {
		ref := m[1]
		require.True(t, strings.HasPrefix(ref, "/swagger/ui/"), "%s: not under the fixed same-origin path", ref)
		r, body := get(ref)
		require.Equal(t, http.StatusOK, r.StatusCode, ref)
		assert.NotEmpty(t, body, ref)
		assert.NotContains(t, r.Header.Get("Content-Type"), "text/html", "%s was answered with the SPA shell", ref)
		assert.Equal(t, "nosniff", r.Header.Get("X-Content-Type-Options"), ref)
	}

	// The spec the page loads is served by the same origin.
	r, spec := get("/openapi.yaml")
	assert.Equal(t, http.StatusOK, r.StatusCode)
	assert.NotEmpty(t, spec)
}
