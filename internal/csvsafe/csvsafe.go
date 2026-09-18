// Package csvsafe neutralises spreadsheet formula injection (CWE-1236) in CSV cells.
//
// It is a deliberately zero-dependency leaf package so every layer that emits a CSV export
// (internal/core, internal/cli, server/http/handlers) shares ONE implementation of the
// neutralisation logic instead of carrying its own copy. Three byte-identical copies used to
// live in those layers, kept separate only to respect the import layering (core must not import
// cli or the http handlers); a leaf package all three can import achieves the same layering
// without the drift risk of triplicating security-critical code.
package csvsafe

// Neutralize prefixes a single quote to any value beginning with =, +, -, @, TAB, or CR so that
// Excel / LibreOffice / Sheets treat the cell as text rather than executing it as a formula.
// Apply it to any user- or server-supplied free-text field written to a CSV export an auditor
// (or any spreadsheet user) may open. An empty string is returned unchanged.
func Neutralize(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}
