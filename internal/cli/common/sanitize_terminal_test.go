// sanitize_terminal_test.go — #G69: SanitizeForTerminal was promoted here from
// internal/cli/secret/import.go's package-local sanitizeForTerminal (kept there
// as a thin alias, still covered by that package's own extensive test suite) so
// every CLI table/report renderer across the codebase can share one
// implementation instead of re-deriving it ad hoc or omitting it entirely.
package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSanitizeForTerminal_StripsControlAndANSI(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "hello", "hello"},
		{"ansi_escape", "\x1b[2Khidden\x1b[0m", "[2Khidden[0m"},
		{"cr_lf", "line1\r\nline2", "line1line2"},
		{"nul", "a\x00b", "ab"},
		{"tab_normalized", "a\tb", "a b"},
		{"bell", "a\x07b", "ab"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, SanitizeForTerminal(tc.in))
		})
	}
}

// TestSanitizeForTerminal_NeutralizesCursorHidingSequence pins the exact attack
// this exists to close: a table/report row containing an attacker-controlled
// free-text field (username, project name, description, ...) that tries to move
// the cursor up and overwrite a prior row a reviewing operator is looking at.
func TestSanitizeForTerminal_NeutralizesCursorHidingSequence(t *testing.T) {
	malicious := "\x1b[1A\x1b[2K  spoofed row pretending to be legitimate\n"
	out := SanitizeForTerminal(malicious)
	assert.NotContains(t, out, "\x1b")
}
