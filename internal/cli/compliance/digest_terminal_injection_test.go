// digest_terminal_injection_test.go — #G69: the compliance digest printed its
// title/body straight through fmt.Println/fmt.Print with no sanitization; this
// is auditor-facing evidence output and any free text folded into it must not
// be able to embed terminal escape sequences that overwrite or hide prior
// output. Body sanitization is line-by-line so its intentional multi-line
// formatting survives (only CR/ANSI/other control bytes within a line strip).
package compliance

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDigest_NeutralizesEscapeSequences(t *testing.T) {
	malicious := "\x1b[1A\x1b[2K  + spoofed clean title"
	maliciousBody := "line one\n\x1b[1A\x1b[2K  + spoofed clean line\nline three"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{
			"title": malicious, "body": maliciousBody,
		}})
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	origSend := digestSend
	t.Cleanup(func() { digestSend = origSend })
	digestSend = false

	out := captureStdout(t, func() { require.NoError(t, digestCmd.RunE(digestCmd, nil)) })
	assert.NotContains(t, out, "\x1b")
	// The body's legitimate newlines must survive sanitization.
	assert.Contains(t, out, "line one")
	assert.Contains(t, out, "line three")
}

func TestSanitizeDigestBody_PreservesNewlines(t *testing.T) {
	in := "a\r\x1b[2Kb\nc\td"
	out := sanitizeDigestBody(in)
	// Only the raw CR/ESC control bytes are stripped (matching
	// common.SanitizeForTerminal's own documented behavior) — the printable
	// CSI text that followed ESC is left as inert text, and the line's own
	// newline boundary survives.
	assert.Equal(t, "a[2Kb\nc d", out)
}
