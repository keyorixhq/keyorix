// Package csvsafe neutralises spreadsheet formula injection (CWE-1236) in CSV cells.
//
// It is a deliberately zero-dependency leaf package so every layer that emits a CSV export
// (internal/core, internal/cli, server/http/handlers) shares ONE implementation of the
// neutralisation logic instead of carrying its own copy. Three byte-identical copies used to
// live in those layers, kept separate only to respect the import layering (core must not import
// cli or the http handlers); a leaf package all three can import achieves the same layering
// without the drift risk of triplicating security-critical code.
package csvsafe

import "strings"

// Neutralize prefixes a single quote to any value beginning with =, +, -, @, TAB, CR or LF, or
// with the full-width forms of the first four (U+FF1D, U+FF0B, U+FF0D, U+FF20), so that
// Excel / LibreOffice / Sheets treat the cell as text rather than executing it as a formula.
// This is OWASP's CSV-injection trigger list
// (TestNeutralize_OWASPTriggerList). Apply it to any user- or server-supplied free-text field
// written to a CSV export an auditor (or any spreadsheet user) may open. An empty string is
// returned unchanged.
func Neutralize(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r', '\n':
		return "'" + s
	}
	for _, p := range fullWidthTriggers {
		if strings.HasPrefix(s, p) {
			return "'" + s
		}
	}
	return s
}

// fullWidthTriggers are the full-width equals, plus, minus and at signs, which some
// spreadsheet locales accept as the start of a formula.
var fullWidthTriggers = [...]string{"\uff1d", "\uff0b", "\uff0d", "\uff20"}
