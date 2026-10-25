package quote

import (
	"strings"
	"testing"
)

// lexPGStringLiteral scans one PostgreSQL string constant at the start of sql the way
// the server's lexer does (scan.l): an optional E/e prefix, then '...' with a doubled quote as an
// embedded quote. Backslash is an escape character inside an E'...' string always, and
// inside a plain '...' string only when standard_conforming_strings is off. It returns the
// decoded value and whatever SQL follows the closing quote; ok is false when the
// constant is unterminated or malformed.
//
// Unlike decodePGQuoted (postgres_fuzz_test.go), which reverses the encoder's own
// transform and so cannot disagree with it, this models the server, including the
// non-default standard_conforming_strings=off mode.
func lexPGStringLiteral(sql string, scs bool) (val, rest string, ok bool) {
	i := 0
	escapes := !scs
	if i < len(sql) && (sql[i] == 'E' || sql[i] == 'e') {
		escapes = true
		i++
	}
	if i >= len(sql) || sql[i] != '\'' {
		return "", "", false
	}
	i++
	var b strings.Builder
	for i < len(sql) {
		c := sql[i]
		switch {
		case c == '\'':
			if i+1 < len(sql) && sql[i+1] == '\'' {
				b.WriteByte('\'')
				i += 2
				continue
			}
			return b.String(), sql[i+1:], true
		case c == '\\' && escapes:
			if i+1 >= len(sql) {
				return "", "", false
			}
			// Only the escapes an encoder could emit matter here; any other \x
			// decodes to x (or a control byte) and so cannot equal the input.
			b.WriteByte(sql[i+1])
			i += 2
		default:
			b.WriteByte(c)
			i++
		}
	}
	return "", "", false
}

// TestQuoteLiteral_SafeWithStandardConformingStringsOff pins that QuoteLiteral's output
// is one complete string constant that decodes back to its input under BOTH settings of
// standard_conforming_strings. PostgresExecutor.Rotate sends
// "ALTER ROLE ... WITH PASSWORD <QuoteLiteral(newValue)>" through pgx Exec with no
// arguments, i.e. the simple query protocol, which runs several ;-separated statements.
// newValue is caller-supplied on on-demand rotation (RotateSecretOnDemand), so on a
// server, database or role where standard_conforming_strings is off, a plain '...' literal
// let `\'` close the string and the rest run as the admin DSN.
func TestQuoteLiteral_SafeWithStandardConformingStringsOff(t *testing.T) {
	payloads := []string{
		`\'; CREATE ROLE kx_injected SUPERUSER; --`,
		`x\`,
		`\`,
		`\\'`,
		`a'b\'c`,
		`''\''`,
		`\x27; SELECT 1; --`,
		"plain-Alnum_123!@#$%^&*-_=+",
		"",
	}
	for _, p := range payloads {
		lit := QuoteLiteral(p)
		for _, scs := range []bool{true, false} {
			val, rest, ok := lexPGStringLiteral(lit, scs)
			if !ok || rest != "" || val != p {
				t.Errorf("QuoteLiteral(%q) = %s; with standard_conforming_strings=%v the server reads value %q then SQL %q (ok=%v)",
					p, lit, scs, val, rest, ok)
			}
		}
	}
}

// TestPrefixAllowed_NonASCIIIsNotABoundary pins #G46's rule for non-ASCII bytes: an
// allowed_refs entry "myapp" must not admit "myappé…" any more than "myapp2", since é is
// a letter, not a delimiter. Role and account names may be non-ASCII
// (core.validateRotationRef only rejects quotes, backslashes, ;, /?#% and controls), and
// isAlnumByte treated every byte >= 0x80 as a segment boundary.
func TestPrefixAllowed_NonASCIIIsNotABoundary(t *testing.T) {
	cases := []struct {
		allowed []string
		ref     string
		want    bool
	}{
		{[]string{"myapp"}, "myappé_admin", false},
		{[]string{"myapp"}, "myapp日本", false},
		{[]string{"appé"}, "appéadmin", false},
		{[]string{"appé"}, "appé", true},
		{[]string{"appé"}, "appé_ro", true},
		{[]string{"myapp"}, "myapp_é", true},
		{[]string{"app_"}, "app_é", true},
		{[]string{"myapp"}, "myapp2", false},
		{[]string{"myapp"}, "myapp-ro", true},
	}
	for _, tc := range cases {
		if got := PrefixAllowed(tc.allowed, tc.ref); got != tc.want {
			t.Errorf("PrefixAllowed(%q, %q) = %v, want %v", tc.allowed, tc.ref, got, tc.want)
		}
	}
}
