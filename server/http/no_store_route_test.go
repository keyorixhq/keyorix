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

// TestNoStore_ScopedToAPI confirms every API response carries Cache-Control: no-store
// (even an unauthenticated 401, since the middleware runs before auth), while non-API
// paths keep their own caching — secret values must never sit in a browser/proxy cache.
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

	// A non-API path keeps its own cache policy, not no-store (health sets no-cache).
	_, cc = cacheCtl("/health")
	assert.NotEqual(t, "no-store", cc, "non-API responses keep their own cache headers")
}
