// terminal_injection_test.go — #G69: the access-review table printed
// attacker-controlled principal name/email/secret name/role name straight
// through fmt.Printf with no sanitization, letting the reviewed principal
// hide or spoof their own recertification row.
package accessreview

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

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

func TestAccessReview_NeutralizesEscapeSequences(t *testing.T) {
	malicious := "\x1b[1A\x1b[2K  + spoofed clean row"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := struct {
			Entries []entryView `json:"entries"`
			Count   int         `json:"count"`
		}{
			Entries: []entryView{{
				PrincipalType: "user", PrincipalName: malicious, Email: malicious,
				Source: "owner", SecretName: malicious, AccessLevel: "read",
			}},
			Count: 1,
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": body})
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	origProject := flagProject
	t.Cleanup(func() { flagProject = origProject })
	flagProject = 1

	out, err := captureStdout(t, func() error { return AccessReviewCmd.RunE(AccessReviewCmd, nil) })
	require.NoError(t, err)
	assert.NotContains(t, out, "\x1b")
}
