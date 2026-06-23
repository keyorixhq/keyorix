package http

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStaticAssets_RejectMutatingMethods confirms the web-UI handlers serve only GET/HEAD:
// a mutating method on a static asset (or an unmatched non-API page path) gets a 405,
// rather than http.FileServer serving the file with a 200 (it ignores the method).
func TestStaticAssets_RejectMutatingMethods(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	router, err := NewRouter(&config.Config{}, newTestCore(t))
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()
	client := &http.Client{}

	do := func(method, path string) int {
		req, err := http.NewRequest(method, srv.URL+path, nil)
		require.NoError(t, err)
		resp, err := client.Do(req)
		require.NoError(t, err)
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	for _, asset := range []string{"/sw.js", "/manifest.json", "/favicon.ico", "/assets/x.js", "/static/x.css"} {
		for _, m := range []string{http.MethodDelete, http.MethodPut, http.MethodPost, http.MethodPatch} {
			assert.Equal(t, http.StatusMethodNotAllowed, do(m, asset), "%s %s must be 405", m, asset)
		}
		assert.NotEqual(t, http.StatusMethodNotAllowed, do(http.MethodGet, asset), "GET %s is allowed", asset)
	}

	// SPA fallback (unmatched, non-API page path): mutating → 405, GET → served (not 405).
	assert.Equal(t, http.StatusMethodNotAllowed, do(http.MethodDelete, "/admin/users"))
	assert.NotEqual(t, http.StatusMethodNotAllowed, do(http.MethodGet, "/admin/users"))

	// API paths are unaffected: they keep their own handling (an unmatched /api/v1 path
	// goes through the auth middleware → 401; a real route → its own auth), never the
	// static 405.
	assert.NotEqual(t, http.StatusMethodNotAllowed, do(http.MethodDelete, "/api/v1/does-not-exist"),
		"API paths keep their own handling, not the static 405")
	assert.NotEqual(t, http.StatusMethodNotAllowed, do(http.MethodGet, "/api/v1/secrets"))
}
