// terminal_injection_test.go — #G69: printBillingReport printed the attacker-
// controlled ProjectName straight through fmt.Fprintf with no sanitization,
// letting a crafted project name embed terminal escape sequences that
// overwrite, hide, or spoof rows in a reviewing operator's terminal.
package billing

import (
	"io"
	"os"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
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

func TestPrintBillingReport_NeutralizesEscapeSequences(t *testing.T) {
	malicious := "\x1b[1A\x1b[2K  + spoofed clean row"
	report := &storage.BillingReport{
		From: time.Now(), To: time.Now(), GeneratedAt: time.Now(),
		Projects: []storage.BillingProjectStat{{ProjectID: 1, ProjectName: malicious}},
	}
	out, err := captureStdout(t, func() error { return printBillingReport(report) })
	require.NoError(t, err)
	assert.NotContains(t, out, "\x1b")
}
