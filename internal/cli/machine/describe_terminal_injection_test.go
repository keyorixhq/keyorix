// describe_terminal_injection_test.go — #G69: runDescribe printed attacker-
// controlled Name/Description straight through fmt.Printf with no
// sanitization.
package machine

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunDescribe_NeutralizesEscapeSequences(t *testing.T) {
	malicious := "\x1b[1A\x1b[2K  + spoofed clean row"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/projects":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"projects": []map[string]any{{"id": 1, "name": "proj"}},
			}})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"machine_identities": []map[string]any{{
					"id": 1, "name": malicious, "identity_type": "ci", "state": "active", "description": malicious,
				}},
			}})
		}
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	origProject := describeProjectName
	t.Cleanup(func() { describeProjectName = origProject })
	describeProjectName = "proj"

	out := captureStdout(t, func() { require.NoError(t, runDescribe(describeCmd, []string{"1"})) })
	assert.NotContains(t, out, "\x1b")
}
