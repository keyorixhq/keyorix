// terminal_injection_test.go — #G69: printRollup printed the attacker-
// controlled ProjectName straight through fmt.Printf with no sanitization,
// letting a crafted project name embed terminal escape sequences that
// overwrite, hide, or spoof rows in this deployment-wide rollup.
package hygiene

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPrintRollup_NeutralizesEscapeSequences(t *testing.T) {
	malicious := "\x1b[1A\x1b[2K  + spoofed clean row"
	r := &rollup{
		Projects: []projectBreakdown{{ProjectID: 1, ProjectName: malicious}},
	}
	out := captureStdout(t, func() { printRollup(r) })
	assert.NotContains(t, out, "\x1b")
}
