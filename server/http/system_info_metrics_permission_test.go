// system_info_metrics_permission_test.go proves the fix moving GET /api/v1/system/info
// and GET /api/v1/system/metrics from the /system route group's system.write gate
// (meant for the RemoteStorage server-to-server proxy API, ADR-049) to a standalone
// system.read gate, matching the auth-config/encryption-config precedent and what
// openapi.yaml already documented. It proves the boundary in both directions: a
// system_viewer-baseline caller (system.read only) now succeeds, and a caller holding
// no relevant permission at all still fails.
package http

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
)

func TestSystemInfoMetrics_PermissionTiers(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	cfg := &config.Config{}
	testCore := newTestCore(t)
	router, err := NewRouter(cfg, testCore)
	require.NoError(t, err)
	server := httptest.NewServer(router)
	defer server.Close()

	createTestToken(t, testCore) // bootstrap admin + seed roles/permissions
	noPermToken := createNoPermissionToken(t, testCore)
	baselineToken := createLimitedToken(t, testCore) // system_viewer only (system.read)

	client := &http.Client{Timeout: 10 * time.Second}
	get := func(token, path string) *http.Response {
		req, err := http.NewRequest(http.MethodGet, server.URL+path, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		require.NoError(t, err)
		t.Cleanup(func() { _ = resp.Body.Close() })
		return resp
	}

	t.Run("baseline_system_viewer_allowed_info", func(t *testing.T) {
		resp := get(baselineToken, "/api/v1/system/info")
		assert.Equal(t, http.StatusOK, resp.StatusCode,
			"a system_viewer-baseline (system.read only) caller must now succeed at /system/info")
	})

	t.Run("baseline_system_viewer_allowed_metrics", func(t *testing.T) {
		resp := get(baselineToken, "/api/v1/system/metrics")
		assert.Equal(t, http.StatusOK, resp.StatusCode,
			"a system_viewer-baseline (system.read only) caller must now succeed at /system/metrics")
	})

	t.Run("no_permission_at_all_still_denied_info", func(t *testing.T) {
		resp := get(noPermToken, "/api/v1/system/info")
		assert.Equal(t, http.StatusForbidden, resp.StatusCode,
			"the fix widens access to system.read, not to every authenticated caller")
	})

	t.Run("no_permission_at_all_still_denied_metrics", func(t *testing.T) {
		resp := get(noPermToken, "/api/v1/system/metrics")
		assert.Equal(t, http.StatusForbidden, resp.StatusCode,
			"the fix widens access to system.read, not to every authenticated caller")
	})
}
