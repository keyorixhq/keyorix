// terminal_injection_test.go — #G69: risk list rendered exception Title/
// Category/Justification unescaped while only Reference was quoted (%q) —
// an inconsistent terminal-escape neutralization.
package risk

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRiskList_NeutralizesEscapeSequences(t *testing.T) {
	malicious := "\x1b[1A\x1b[2K  + spoofed clean row"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := struct {
			Exceptions []exceptionView `json:"exceptions"`
		}{
			Exceptions: []exceptionView{{
				ID: 1, Title: malicious, Category: malicious, Reference: "REF-1",
				Justification: malicious, Status: "pending", ExpiresAt: "2026-12-01",
			}},
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": body})
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	out := captureStdout(t, func() { require.NoError(t, listCmd.RunE(listCmd, nil)) })
	assert.NotContains(t, out, "\x1b")
}
