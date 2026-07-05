package rotation

import (
	"strings"
	"testing"
)

// FuzzMySQLQuoteString fuzzes quoteMySQLString (mysql.go) — hand-rolled SQL
// escaping at the same trust boundary (an admin-configured rotation_ref)
// that already produced one real, shipped, fixed vulnerability in this
// codebase (FuzzAzureGenerateUpstreamRef's subject). See the doc comment on
// FuzzPostgresQuoteIdentifier (postgres_fuzz_test.go) for why a round-trip
// invariant is the strongest available proxy for "no input can escape the
// quoted context" without a live SQL parser.
//
// quoteMySQLString's encode order is: (1) double every backslash, THEN (2)
// double every single-quote, then wrap in single quotes. Decoding must undo
// these in the OPPOSITE order — undo (2) first (un-double quotes), THEN
// undo (1) (un-double backslashes) — or the reconstruction is wrong.
//
// Hand-traced example proving the order, input `\'` (one backslash, one
// single-quote), reproduced here as the derivation for decodeMySQLQuoted
// below (B = backslash byte, Q = single-quote byte):
//
//	s          = B Q                          (2 bytes)
//	encode (1): double every B  -> B B Q       (3 bytes)
//	encode (2): double every Q  -> B B Q Q     (4 bytes)
//	wrap        -> Q B B Q Q Q                 (6 bytes: quoteMySQLString(`\'`) == `'\\'''`)
//
//	decode, stripped of the wrapping quotes -> B B Q Q (4 bytes)
//	decode (2) undo quote-doubling first: "QQ"->"Q"  -> B B Q   (3 bytes)
//	decode (1) undo backslash-doubling second: "BB"->"B" -> B Q (2 bytes) == s. Correct.
//
// (Doing it in the wrong order — backslash-undouble before quote-undouble —
// happens to also recover B Q for this particular example, since B-runs and
// Q-runs never overlap positionally; but the comment above documents the
// mathematically-correct reverse-of-encode order regardless, and the fuzz
// target below proves it holds for the whole input space, not just this one
// hand-traced case.)
func decodeMySQLQuoted(quoted string) (string, bool) {
	if len(quoted) < 2 || quoted[0] != '\'' || quoted[len(quoted)-1] != '\'' {
		return "", false
	}
	inner := quoted[1 : len(quoted)-1]
	inner = strings.ReplaceAll(inner, `''`, `'`) // undo step 2 (quote-doubling) first
	inner = strings.ReplaceAll(inner, `\\`, `\`) // then undo step 1 (backslash-doubling)
	return inner, true
}

// FuzzMySQLQuoteString round-trips quoteMySQLString: decodeMySQLQuoted must
// exactly recover any fuzzed input.
//
// NUL bytes and other control characters: MySQL's own wire protocol/text
// protocol handling can reject or special-case a NUL byte in some contexts
// independent of application-level quoting — so, as with the Postgres
// targets, a round-trip failure specifically and only on NUL/control-byte
// input would be a protocol-level scope boundary, not a SQL-injection-
// relevant escaping bug. quoteMySQLString itself operates purely at the Go
// string level (no NUL-stripping), so the round-trip is still asserted for
// these seeds below — the escaping itself must remain lossless.
func FuzzMySQLQuoteString(f *testing.F) {
	f.Add("")
	f.Add("a")
	f.Add(`'`)
	f.Add(`\`)
	f.Add(`\'`)
	f.Add(`'\`)
	f.Add(`a'b\c`)
	f.Add(`''''`)
	f.Add(`\\\\`)
	f.Add(`a\'b\'c`)
	f.Add("rotation_user")
	f.Add("app-role.prod_01@%")
	f.Add("\x00")
	f.Add("a\x00\x01\x02b")
	f.Add(strings.Repeat(`'`, 200))
	f.Add(strings.Repeat(`\`, 200))
	f.Add(strings.Repeat(`\'`, 100))

	f.Fuzz(func(t *testing.T, s string) {
		quoted := quoteMySQLString(s)
		got, ok := decodeMySQLQuoted(quoted)
		if !ok {
			t.Fatalf("quoteMySQLString(%q) = %q is not quote-wrapped", s, quoted)
		}
		if got != s {
			t.Fatalf("round-trip mismatch: quoteMySQLString(%q) = %q, decoded back to %q", s, quoted, got)
		}
	})
}
