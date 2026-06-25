package handlers

// csvSafe neutralizes spreadsheet formula injection (CWE-1236): a CSV cell beginning
// with =, +, -, @, TAB, or CR is prefixed with a single quote so Excel / LibreOffice /
// Sheets treat it as text rather than executing it as a formula. Apply it to any
// user-controlled field (secret names, usernames, descriptions) written to a CSV
// export an auditor may open.
func csvSafe(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}
