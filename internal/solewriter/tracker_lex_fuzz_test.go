package solewriter

import (
	"strings"
	"testing"
)

// FuzzClassifyStatement checks the lexer's one-way property: whatever text it
// reads as one complete statement ends outside every literal, quoted
// identifier and comment, so a second statement appended after a newline and
// a ';' is always seen (a fenced write). It also must not panic.
func FuzzClassifyStatement(f *testing.F) {
	for _, s := range []string{
		`SELECT pg_catalog.concat_ws('; ', 'a')`,
		`SELECT 'a''b'`, `SELECT E'\''`, `SELECT $$x$$`, `SELECT $t$x$t$`,
		`SELECT "a""b"`, "SELECT 1 -- c", "SELECT /* /* */ */ 1", `SELECT a$b$`,
		`SELECT $1`, `UPDATE roles SET x = 1`, `SELECT U&'x'`, "ROLLBACK TO sp",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_ = classifyStatement(s, nil)
		clean, ok := lexStatement(s)
		if !ok {
			return
		}
		if strings.Contains(clean, ";") && !strings.ContainsAny(clean, `'"$`) {
			t.Fatalf("lexStatement(%q) kept a top-level ';' in %q", s, clean)
		}
		probe := s + "\n; DELETE FROM roles"
		if got := classifyStatement(probe, nil); got != stmtFencedWrite {
			t.Fatalf("classifyStatement(%q) = %d: the appended DELETE is hidden", probe, got)
		}
	})
}
