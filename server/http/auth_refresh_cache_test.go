package http

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRefreshToken_EvictsOldTokenFromAuthCache is a regression test for the
// token-rotation cache bug: RefreshToken rotates the session (deleting the old one),
// but if it does not evict the old token from the middleware's positive auth cache,
// the rotated-away token keeps passing auth (a cache hit skips the DB) for up to
// validTokenTTL. The fix mirrors Logout/ChangePassword (middleware.InvalidateTokenCache).
func TestRefreshToken_EvictsOldTokenFromAuthCache(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTP: config.ServerInstanceConfig{Enabled: true, Port: "8080"},
		},
	}
	c := newTestCore(t)
	router, err := NewRouter(cfg, c)
	require.NoError(t, err)
	server := httptest.NewServer(router)
	defer server.Close()
	client := server.Client()

	oldToken := createTestToken(t, c)

	authedProfileStatus := func(token string) int {
		req, _ := http.NewRequest("GET", server.URL+"/api/v1/auth/profile", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		require.NoError(t, err)
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	// 1. An authed request validates the old token and caches it (positive entry).
	require.Equal(t, http.StatusOK, authedProfileStatus(oldToken), "token should authenticate before refresh")

	// 2. Refresh rotates the token — the old session row is deleted.
	req, _ := http.NewRequest("POST", server.URL+"/auth/refresh", nil)
	req.Header.Set("Authorization", "Bearer "+oldToken)
	resp, err := client.Do(req)
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "refresh should succeed: %s", body)

	var refreshed struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(body, &refreshed))
	require.NotEmpty(t, refreshed.Data.Token)
	require.NotEqual(t, oldToken, refreshed.Data.Token, "refresh must issue a new token")

	// 3. The OLD token must be rejected immediately: refresh evicted it from the cache,
	//    so the middleware hits the DB and finds no session. Before the fix, the cached
	//    positive entry kept it valid for up to validTokenTTL.
	assert.Equal(t, http.StatusUnauthorized, authedProfileStatus(oldToken),
		"rotated-away token must be rejected, not served from a stale cache entry")

	// 4. The NEW token authenticates.
	assert.Equal(t, http.StatusOK, authedProfileStatus(refreshed.Data.Token), "new token should authenticate")
}
