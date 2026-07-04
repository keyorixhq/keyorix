package common

// CSVSafe neutralizes spreadsheet formula injection (CWE-1236): a CSV cell
// beginning with =, +, -, @, TAB, or CR is prefixed with a single quote so
// Excel / LibreOffice / Sheets treat it as text rather than executing it as a
// formula. Apply it to any server-supplied free-text field (actor names,
// event descriptions, etc.) written to a CSV a CLI command emits, mirroring
// the identical csvSafe convention already applied to the server's own CSV
// export handlers (server/http/handlers/csv_safe.go, #148/#239).
func CSVSafe(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}
