package rotation

import (
	"strings"
	"testing"
)

// naiveDoubleDelim is an independent, byte-by-byte reimplementation of the
// doubling transform quoteIdentifier/quoteLiteral (postgres.go) perform via
// strings.ReplaceAll — deliberately not reusing that call, so this is a
// differential check between two independently-written encodings of the same
// rule, not a tautology. delim is always a single ASCII byte ('"' or '\”),
// which never appears as a UTF-8 continuation byte, so byte-wise scanning is
// safe even for multi-byte input.
func naiveDoubleDelim(s string, delim byte) string {
	var b strings.Builder
	b.WriteByte(delim)
	for i := 0; i < len(s); i++ {
		if s[i] == delim {
			b.WriteByte(delim)
		}
		b.WriteByte(s[i])
	}
	b.WriteByte(delim)
	return b.String()
}

// TestPostgresQuoting_DifferentialNaive pins quoteIdentifier/quoteLiteral's
// exact output, via an independent second implementation, for a curated set
// of edge cases (embedded delimiters, backslashes, NUL/control bytes, long
// repeated-delimiter runs, a max-codepoint rune) — a future refactor of
// either function that silently changes the encoding for one of these shapes
// fails here even if FuzzPostgresQuoting's round-trip invariant alone would
// not catch it.
func TestPostgresQuoting_DifferentialNaive(t *testing.T) {
	cases := []string{
		"", "a", `"`, `'`, `\`, `a"b'c\d`, `""""`, `''''`, `a"'"'"'b`,
		"app_rotation_role", "app-role.prod_01", "\x00", "a\x00\x01\x02b",
		strings.Repeat(`"`, 200), strings.Repeat(`'`, 200),
		strings.Repeat(`"'`, 500), "\x00\x00", "\xff\xfe\x00weird",
		"a" + string(rune(0x10FFFF)) + "b",
	}
	for _, s := range cases {
		if got, want := quoteIdentifier(s), naiveDoubleDelim(s, '"'); got != want {
			t.Fatalf("quoteIdentifier(%q) = %q, naive reimplementation = %q", s, got, want)
		}
		if got, want := quoteLiteral(s), naiveDoubleDelim(s, '\''); got != want {
			t.Fatalf("quoteLiteral(%q) = %q, naive reimplementation = %q", s, got, want)
		}
	}
}
