package core

import "testing"

// Control characters in a user-controlled name/string must be stripped from an audit
// Description so a crafted secret name can't inject a forged audit line or smuggle ANSI
// escapes into a CLI audit viewer.
func TestSanitizeAuditText(t *testing.T) {
	cases := map[string]string{
		"plain secret name":                 "plain secret name",
		"line1\nline2":                      "line1line2", // newline dropped (no forged line)
		"a\r\nFAKE secret.deleted by admin": "aFAKE secret.deleted by admin",
		"esc\x1b[31mred":                    "esc[31mred", // ANSI escape byte dropped
		"nul\x00byte":                       "nulbyte",
		"tab\tcol":                          "tab col",        // tab normalized to space
		"unicode-café-✓":                    "unicode-café-✓", // printable unicode preserved
	}
	for in, want := range cases {
		if got := sanitizeAuditText(in); got != want {
			t.Errorf("sanitizeAuditText(%q) = %q; want %q", in, got, want)
		}
	}
}
