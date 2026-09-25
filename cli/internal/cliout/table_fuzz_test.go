package cliout

import (
	"strings"
	"testing"
	"unicode"
)

// FuzzSanitizeForTerminal is CLI-FUZZ target 1 (ADR-108): SanitizeForTerminal is the
// CLI's sole terminal-injection defense for attacker/server-controlled free text before
// it reaches the user's terminal. The invariant it must uphold for ANY input:
//
//  1. Never panics.
//  2. The output contains no rune for which unicode.IsControl is true -- this covers
//     every C0 control byte (including ESC 0x1B, the lead-in for every CSI/OSC escape
//     sequence) and every C1 control rune, not just a specific escape-sequence
//     blocklist. \t and \n are themselves control runes and are removed/mapped too
//     (the doc comment's "tabs become a single space" -- SanitizeForTerminal does not
//     preserve raw \n either, unlike the task's informal "except \n and \t" framing).
//  3. Idempotent: sanitizing already-sanitized output is a no-op.
func FuzzSanitizeForTerminal(f *testing.F) {
	nel := string(rune(0x85))   // C1 control: Next Line
	csiC1 := string(rune(0x9b)) // C1 control: single-byte CSI

	seeds := []string{
		"",
		"plain text",
		"tab\tseparated",
		"newline\nhere",
		"\x1b[31mred\x1b[0m",       // CSI color escape
		"\x1b]0;evil title\x07",    // OSC window-title injection
		"\x1bP+q evil\x1b\\",       // DCS
		"\x00\x01\x02\x03",         // C0 controls
		nel + csiC1,                // C1 controls
		"café",                     // non-control multibyte, must survive
		"\xff\xfe not valid utf8",  // invalid UTF-8 bytes
		string([]byte{0x1b, 0x5b}), // truncated CSI lead-in
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		var out string
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("SanitizeForTerminal panicked on %q: %v", s, r)
				}
			}()
			out = SanitizeForTerminal(s)
		}()

		for _, r := range out {
			if unicode.IsControl(r) {
				t.Fatalf("SanitizeForTerminal(%q) = %q still contains control rune %U", s, out, r)
			}
		}

		if strings.ContainsRune(out, 0x1b) {
			t.Fatalf("SanitizeForTerminal(%q) = %q still contains ESC", s, out)
		}

		again := SanitizeForTerminal(out)
		if again != out {
			t.Fatalf("SanitizeForTerminal is not idempotent: SanitizeForTerminal(%q) = %q, but SanitizeForTerminal(that) = %q", s, out, again)
		}
	})
}
