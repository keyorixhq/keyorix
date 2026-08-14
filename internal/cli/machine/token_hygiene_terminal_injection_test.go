// token_hygiene_terminal_injection_test.go — #G69: the token-hygiene report
// printed attacker-controlled Name text straight through fmt.Printf with no
// sanitization — admin-only and cross-tenant, so the blast radius spans every
// tenant.
package machine

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenHygiene_NeutralizesEscapeSequences(t *testing.T) {
	malicious := "\x1b[1A\x1b[2K  + spoofed clean row"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"tokens": []map[string]any{{
				"id": 1, "machine_identity_id": 1, "name": malicious,
				"token_prefix": "kx_mach_ab", "last_used_at": "", "expired": true, "stale": false,
			}},
		}})
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	out := captureStdout(t, func() { require.NoError(t, tokenHygieneCmd.RunE(tokenHygieneCmd, nil)) })
	assert.NotContains(t, out, "\x1b")
}
