package http

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
)

// IDENTITY-FOLD-SPACE-WIDTH over REST: the user create/update request bodies
// only check username length, so the core rule is what refuses a look-alike
// username; it must come back as 400, not 500. Role names were already refused
// by the decoder's `identifier` tag; pinned here so the two layers agree.
func TestREST_IdentityNameRule(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	testCore := newTestCore(t)
	token := createTestToken(t, testCore)
	router, err := NewRouter(&config.Config{Server: config.ServerConfig{HTTP: config.ServerInstanceConfig{Enabled: true, Port: "8080"}}}, testCore)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()
	client := &http.Client{Timeout: 10 * time.Second}

	send := func(method, path string, body map[string]any) (int, map[string]any) {
		t.Helper()
		b, err := json.Marshal(body)
		require.NoError(t, err)
		req, err := http.NewRequest(method, srv.URL+path, bytes.NewReader(b))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	const pw = "Qr7#Kp2$Lm5@Vn9!"
	spoofed := []string{"ａｄｍｉｎ", "ad min", "admin ", " admin", "ad  min"}

	for i, name := range spoofed {
		code, out := send("POST", "/api/v1/users", map[string]any{
			"username": name, "email": fmt.Sprintf("spoof%d@example.com", i), "display_name": "Spoof", "password": pw,
		})
		assert.Equal(t, http.StatusBadRequest, code, "create %q: %v", name, out)
	}

	code, out := send("POST", "/api/v1/users", map[string]any{
		"username": "john.developer", "email": "john@example.com", "display_name": "John", "password": pw,
	})
	require.Equal(t, http.StatusCreated, code, "control create: %v", out)
	data, _ := out["data"].(map[string]any)
	idf, ok := data["id"].(float64)
	require.True(t, ok, "created user id in %v", out)
	userPath := fmt.Sprintf("/api/v1/users/%d", int(idf))

	for _, name := range spoofed {
		code, out := send("PUT", userPath, map[string]any{"username": name})
		assert.Equal(t, http.StatusBadRequest, code, "rename to %q: %v", name, out)
	}
	code, out = send("PUT", userPath, map[string]any{"username": "john.developer", "display_name": "John D"})
	assert.Equal(t, http.StatusOK, code, "echoing the unchanged username is not a rename: %v", out)

	for _, name := range []string{"ｏｐｓ_team", "ops team", "ops team ", "ops  team"} {
		code, out := send("POST", "/api/v1/roles", map[string]any{"name": name, "description": "d"})
		assert.Equal(t, http.StatusBadRequest, code, "role %q: %v", name, out)
	}
}
