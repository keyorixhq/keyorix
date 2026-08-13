// terminal_injection_test.go — #G69: the anomalies list printed attacker-
// controlled secret name/accessed-by/description straight through fmt.Printf
// with no sanitization, letting the actor who triggered the alert hide or
// spoof it.
package anomalies

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	fnErr := fn()

	require.NoError(t, w.Close())
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(out), fnErr
}

func TestRunListRemote_NeutralizesEscapeSequences(t *testing.T) {
	malicious := "\x1b[1A\x1b[2K  + spoofed clean row"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := anomalyListResponse{
			Alerts: []anomalyAlert{{
				ID: 1, SecretName: malicious, AlertType: "new_ip", Severity: "high",
				Description: malicious, AccessedBy: malicious, IPAddress: malicious,
				DetectedAt: "2026-08-13T00:00:00Z",
			}},
			Total: 1,
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": resp})
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	out, err := captureStdout(t, func() error { return runListRemote(rc) })
	require.NoError(t, err)
	assert.NotContains(t, out, "\x1b")
}
