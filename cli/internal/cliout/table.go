// Package cliout holds the thin CLI's shared table/formatting helpers, so every
// command group (pat, machine, and future Phase 3 PRs per docs/cli-split-inventory.md
// §7) renders tabular output the same way instead of each hand-rolling its own
// tabwriter setup.
package cliout

import (
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"unicode"
)

// Table accumulates a header and rows, then renders them tab-aligned on Flush.
// Matches the old CLI's tabwriter convention (0, 0, 2, ' ', 0) so migrated
// commands keep byte-for-byte identical column spacing.
type Table struct {
	w *tabwriter.Writer
}

// NewTable returns a Table writing to out, with header as the first row.
func NewTable(out io.Writer, header ...string) *Table {
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, strings.Join(header, "\t")) //nolint:errcheck
	return &Table{w: w}
}

// NewStdoutTable is NewTable against os.Stdout, the common case.
func NewStdoutTable(header ...string) *Table {
	return NewTable(os.Stdout, header...)
}

// Row appends one row. Each field is rendered with fmt.Sprint and joined with tabs.
func (t *Table) Row(fields ...any) {
	strs := make([]string, len(fields))
	for i, f := range fields {
		strs[i] = fmt.Sprint(f)
	}
	fmt.Fprintln(t.w, strings.Join(strs, "\t")) //nolint:errcheck
}

// Flush writes the accumulated table to the underlying writer.
func (t *Table) Flush() error {
	return t.w.Flush()
}

// CSVSafe prefixes a single quote to any value beginning with =, +, -, @, TAB, or CR so
// that Excel / LibreOffice / Sheets treat the cell as text rather than executing it as a
// formula (CWE-1236). Apply it to any user- or server-supplied free-text field written to
// a CSV export. An empty string is returned unchanged. Mirrors the old CLI's
// internal/csvsafe.Neutralize exactly -- reimplemented here (not imported) since this
// module cannot depend on internal/csvsafe (a main-module internal/ package; see
// internal/depguard's whole reason for existing).
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

// SanitizeForTerminal strips control characters (tabs become a single space) from
// attacker-controlled free text (names, descriptions) before printing it, so a
// crafted value can't inject terminal escape sequences or corrupt column alignment.
// Mirrors the old CLI's internal/cli/common.SanitizeForTerminal exactly.
func SanitizeForTerminal(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\t' {
			return ' '
		}
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}
