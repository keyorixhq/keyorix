// status_s3_test.go — sprint-3 coverage additions for the status package.
// Targets: runStatus's "Unhealthy" branch (service initializes but HealthCheck
// fails) and runPing's per-iteration "Failed" branch + "Partial connectivity"
// summary branch (some pings succeed, some fail against the same backend).
package status

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
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

// TestRunPing_PartialConnectivity exercises runPing's per-iteration "Failed"
// branch (HealthCheck errors after a successful InitializeCoreService) and the
// "Partial connectivity" summary branch (0 < successCount < pingCount) by
// pointing at a real server that succeeds on the first health check and fails
// on the rest.
//
// G80 Wave 0c: rewritten to fail via HTTP 404 instead of a fabricated
// {"success":false,...} 200 body — see TestRunStatus_RemoteUnhealthy's comment;
// the real /health endpoint cannot produce the latter, and 404 (not 5xx) keeps
// this test's "N pings → N handler calls" assumption true without needing to
// fight isRetryableError's 5xx retry behavior.
//
// Note: runPing sleeps 1s between iterations so this test takes ~2s.
func TestRunPing_PartialConnectivity(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintln(w, `{"status":"healthy"}`)
			return
		}
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

	orig := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	require.NoError(t, runPing(nil, nil))
	_ = w.Close()
	outBytes, _ := io.ReadAll(r)
	out := string(outBytes)

	assert.Contains(t, out, "Ping 1: ✅ Success")
	assert.Contains(t, out, "Ping 2: ❌ Failed (health check failed:")
	assert.Contains(t, out, "Ping 3: ❌ Failed (health check failed:")
	assert.Contains(t, out, "Successful:     1")
	assert.Contains(t, out, "Failed:         2")
	assert.Contains(t, out, "Status:         ⚠️  Partial connectivity")
	assert.Equal(t, int32(3), calls.Load())
}
