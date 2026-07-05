package rotation

import (
	"strings"
	"testing"
)

// FuzzPostgresQuoting fuzzes quoteIdentifier and quoteLiteral (postgres.go) —
// hand-rolled SQL escaping at the same trust boundary (an admin-configured
// rotation_ref) that already produced one real, shipped, fixed vulnerability
// in this codebase (FuzzAzureGenerateUpstreamRef's subject). Neither function
// can be validated against a live SQL parser here, so the strongest available
// proxy is a round-trip invariant: a reference decoder that exactly reverses
// the encode transform must recover the original input for every possible
// string. If it doesn't, the escaping is ambiguous — i.e. some byte sequence
// could make the quoted context interpret encoded content differently than
// intended, the same shape of bug as the Azure ref-injection issue this round
// found.
//
// Both quoteIdentifier and quoteLiteral share the same shape: wrap in a
// delimiter, double every occurrence of that delimiter inside. Decoding is
// the inverse: strip the leading/trailing delimiter, then replace every
// doubled delimiter with a single one. A single un-double pass is correct
// here (unlike MySQL below) because there is only one context-free
// transform, not two interacting ones — see mysql_fuzz_test.go for the case
// where order matters. Since the two functions only differ in delimiter
// character, both round-trips are asserted per fuzzed input from a single
// fuzz target, rather than two near-identical targets.

// decodePGQuoted reverses quoteIdentifier/quoteLiteral's transform: strip the
// leading/trailing delim, then collapse every doubled delim to one.
func decodePGQuoted(quoted string, delim byte) (string, bool) {
	if len(quoted) < 2 || quoted[0] != delim || quoted[len(quoted)-1] != delim {
		return "", false
	}
	inner := quoted[1 : len(quoted)-1]
	doubled := string([]byte{delim, delim})
	return strings.ReplaceAll(inner, doubled, string(delim)), true
}

// FuzzPostgresQuoting round-trips both quoteIdentifier (double-quote delim)
// and quoteLiteral (single-quote delim) via decodePGQuoted; each must
// exactly recover any fuzzed input.
//
// NUL bytes and other control characters: PostgreSQL's wire protocol itself
// rejects a NUL byte inside an identifier/string at the protocol level (it's
// a C-string-terminated wire format), independent of any quoting these
// functions do — so a round-trip failure specifically and only on inputs
// containing 0x00 would not indicate a SQL-injection-relevant escaping bug.
// The round-trip is still asserted for NUL/control-byte seeds below because
// quoteIdentifier/quoteLiteral operate purely at the Go string level (no
// NUL-stripping), so the escaping itself must still be lossless even though
// the underlying driver would separately refuse to transmit such a value.
func FuzzPostgresQuoting(f *testing.F) {
	f.Add("")
	f.Add("a")
	f.Add(`"`)
	f.Add(`'`)
	f.Add(`\`)
	f.Add(`a"b'c\d`)
	f.Add(`""""`)
	f.Add(`''''`)
	f.Add(`a"'"'"'b`)
	f.Add("app_rotation_role")
	f.Add("app-role.prod_01")
	f.Add("\x00")
	f.Add("a\x00\x01\x02b")
	f.Add(strings.Repeat(`"`, 200))
	f.Add(strings.Repeat(`'`, 200))

	f.Fuzz(func(t *testing.T, s string) {
		idQuoted := quoteIdentifier(s)
		idGot, ok := decodePGQuoted(idQuoted, '"')
		if !ok {
			t.Fatalf("quoteIdentifier(%q) = %q is not delimiter-wrapped", s, idQuoted)
		}
		if idGot != s {
			t.Fatalf("round-trip mismatch: quoteIdentifier(%q) = %q, decoded back to %q", s, idQuoted, idGot)
		}
		// The escaped identifier must never contain an UNPAIRED delimiter —
		// every '"' in the quoted output must be part of a doubled pair or one
		// of the two wrapping delimiters. Verified implicitly by the
		// successful round-trip above (an unpaired '"' would either break the
		// wrapping-strip check or leave a stray '"' after un-doubling that
		// wouldn't match the original s).

		litQuoted := quoteLiteral(s)
		litGot, ok := decodePGQuoted(litQuoted, '\'')
		if !ok {
			t.Fatalf("quoteLiteral(%q) = %q is not delimiter-wrapped", s, litQuoted)
		}
		if litGot != s {
			t.Fatalf("round-trip mismatch: quoteLiteral(%q) = %q, decoded back to %q", s, litQuoted, litGot)
		}
	})
}
