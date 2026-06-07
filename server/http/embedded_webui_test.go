package http

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// With no on-disk web assets configured, the server serves the web UI from the
// embedded build (the placeholder in test builds, the real SPA in release
// builds), and the SPA fallback must not shadow API routes.
func TestEmbeddedWebUI(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	router, err := NewRouter(&config.Config{}, core.NewKeyorixCore(store.NewLocalStorage(db)))
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()
	client := &http.Client{}

	// Root serves the embedded index.html.
	resp, err := client.Get(srv.URL + "/")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := readAll(t, resp.Body)
	_ = resp.Body.Close()
	assert.Contains(t, body, "Keyorix", "embedded index.html should be served at /")
	assert.Contains(t, resp.Header.Get("Content-Type"), "text/html")

	// A client-side route also resolves to index.html (SPA fallback).
	resp, err = client.Get(srv.URL + "/admin/users")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	// API routes are NOT shadowed by the SPA fallback — an unauthenticated API
	// call returns 401, not the HTML page.
	resp, err = client.Get(srv.URL + "/api/v1/secrets")
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "API routes must not fall through to the SPA")
	_ = resp.Body.Close()
}
