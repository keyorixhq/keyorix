// status_s3_test.go — sprint-3 coverage additions for the status package.
// Targets: runStatus's "Unhealthy" branch (service initializes but HealthCheck
// fails).
package status

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRunStatus_RemoteUnhealthy exercises the branch in runStatus where
// common.InitializeCoreService succeeds (a well-formed remote config with a
// reachable server) but service.HealthCheck returns an error. This is the
// "err != nil" arm of the health-check if/else that the other remote tests
// (which fail at InitializeCoreService itself, before ever reaching
// HealthCheck) don't reach.
//
// G80 Wave 0c: this test originally mocked /health returning HTTP 200 with a
// body of {"success":false,"error":{...}} — the standard /api/v1/* envelope's
// failure shape. That's not a real failure mode: /health
// (server/http/handlers/health.go) is a deliberately minimal, unauthenticated
// k8s-style liveness probe that always returns {"status":"healthy",...}
// unconditionally on a 2xx — it has no code path that ever produces
// success:false, and it isn't an /api/v1/* route so it was never meant to use
// that envelope at all. The old mock was testing a scenario the real server
// cannot produce, which is exactly what let RemoteStorage.Health() ship
// checking resp.Success against a body shape /health never sends — the
// mismatch this fix closes (internal/storage/store/remote_stats.go). A real,
// reachable /health failure is an HTTP-level one; this mocks a 404 (not 5xx —
// isRetryableError, internal/storage/remote/client.go, retries every 5xx and
// 429, which would make this test slow and its call count nondeterministic
// for no benefit: the CLI's error-surfacing path is the same regardless of
// which HTTP status triggered it).
func TestRunStatus_RemoteUnhealthy(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("KEYORIX_REMOTE_API_KEY", "test-api-key")

	writePingConfig(t, dir, srv.URL, 2)

	out := captureStdout(t, func() { require.NoError(t, runStatus(nil, nil)) })

	assert.Contains(t, out, "Storage Type: 🌐 Remote")
	assert.Contains(t, out, "❌ Unhealthy (health check failed:")
	assert.Contains(t, out, "Response Time:")
}
