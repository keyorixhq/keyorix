// terminal_injection_test.go — #G69: printAuditLogTable/printAuditSearchTable
// printed attacker-controlled actor/description text straight through
// fmt.Printf with no sanitization, letting a crafted value embed terminal
// escape sequences that overwrite, hide, or spoof rows in a reviewing
// operator's terminal.
package audit

import (
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	fn()

	require.NoError(t, w.Close())
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(out)
}

func TestPrintAuditLogTable_NeutralizesEscapeSequences(t *testing.T) {
	malicious := "\x1b[1A\x1b[2K  + spoofed clean row\n"
	logs := []logEntry{{
		ID: 1, EventType: "secret.read", Actor: malicious, ActorType: "user",
		Description: malicious, Timestamp: "2026-08-13T00:00:00Z",
	}}
	out := captureStdout(t, func() { printAuditLogTable(logs, 1) })
	assert.NotContains(t, out, "\x1b")
}

func TestPrintAuditSearchTable_NeutralizesEscapeSequences(t *testing.T) {
	malicious := "\x1b[1A\x1b[2K  + spoofed clean row\n"
	events := []searchEvent{{
		ID: 1, EventType: "secret.read", Description: malicious,
		EventTime: "2026-08-13T00:00:00Z", ActorType: "user",
	}}
	out := captureStdout(t, func() { printAuditSearchTable(events, 1) })
	assert.NotContains(t, out, "\x1b")
}
