// terminal_injection_test.go — #G69: printMachineTable/runDescribe/token-hygiene
// table printed attacker-controlled Name/Description text straight through
// fmt.Printf with no sanitization, letting a crafted value embed terminal
// escape sequences that overwrite, hide, or spoof rows in a reviewing
// operator's terminal.
package machine

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
)

func TestPrintMachineTable_NeutralizesEscapeSequences(t *testing.T) {
	malicious := "\x1b[1A\x1b[2K  + spoofed clean row\n"
	identities := []*models.MachineIdentity{{
		ID: 1, Name: malicious, IdentityType: "ci", State: "active", Description: malicious,
	}}
	out := captureStdout(t, func() { printMachineTable(identities, "proj") })
	assert.NotContains(t, out, "\x1b")
}
