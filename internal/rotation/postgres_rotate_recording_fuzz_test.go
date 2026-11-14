package rotation

import (
	"context"
	"strings"
	"testing"
)

// recordingPGConn is a fake pgConn (the executor's injection seam) that records
// every statement handed to Exec instead of touching a database.
type recordingPGConn struct{ stmts []string }

func (r *recordingPGConn) Exec(_ context.Context, sql string) error {
	r.stmts = append(r.stmts, sql)
	return nil
}
func (r *recordingPGConn) Close(context.Context) {}

// FuzzPostgresRotateRecordingDriver is a sink-guided harness for the SQL sink in
// PostgresExecutor.Rotate: a `fmt.Sprintf("ALTER ROLE %s WITH PASSWORD %s", …)`
// that cannot bind parameters (DDL) and is sent over pgx's simple query
// protocol, which executes every ;-separated statement. A recording pgConn
// captures the exact statement the sink would run.
//
//	INVARIANT: for any role ref and password value that reach the sink, the
//	statement the sink executes is EXACTLY `ALTER ROLE <id> WITH PASSWORD <lit>`
//	where <id> is a double-quoted identifier that decodes back to ref and <lit>
//	is an E'…' string literal that decodes back to value — i.e. no
//	attacker-influenced byte escapes its quoted slot into executable SQL.
//
// The decoder below (parseQuotedIdent / parseEString) is written independently
// of quote.QuoteIdentifier / quote.QuoteLiteral, so it is not a tautology: if
// the quoting fails to escape a quote, the recorded statement's quoted slot
// ends early and the decode no longer round-trips to the input, failing the
// harness (see the sinkmap REPORT red-proof run, which broke QuoteIdentifier).
//
// What this oracle does NOT verify:
//   - It records the statement STRING; it does not run it against a real
//     PostgreSQL server, so it cannot see a server-side parse that an exotic
//     encoding might still permit (the leaf FuzzPostgresQuoting covers the
//     escaper semantics; TestQuoteLiteral_SafeWithStandardConformingStringsOff
//     covers the standard_conforming_strings edge).
//   - It drives Rotate with a prefix-allowlisted ref so the SQL path is
//     actually exercised; it does NOT re-test the allow-list or
//     core.validateRotationRef (the layer-one config-time filter that, in
//     production, rejects most of these refs long before the sink). This is
//     deliberately the defense-in-depth layer the enclosing function owns.
//   - round-trip equality is the oracle; it does not independently assert the
//     statement is free of EVERY conceivable injection, only that ref/value
//     occupy exactly their quoted slots and nothing else was emitted.
func FuzzPostgresRotateRecordingDriver(f *testing.F) {
	f.Add(`admin`, `p@ss`)
	f.Add(`"; DROP ROLE victim; --`, `x`)
	f.Add(`role"with"quotes`, `v'al'ue`)
	f.Add(`r`, `'; SELECT 1; --`)
	f.Add(``, `pw`)
	f.Add(`back\slash`, `lit\'eral`)

	ctx := context.Background()
	f.Fuzz(func(t *testing.T, refSuffix, value string) {
		// "r/" is an allow-listed prefix whose trailing '/' is a segment
		// boundary, so any suffix is admitted and the SQL-building path runs.
		ref := "r/" + refSuffix
		if value == "" {
			return // Rotate rejects an empty value before building SQL
		}
		rec := &recordingPGConn{}
		e := NewPostgresExecutor("backend", "postgres://admin@localhost/db", []string{"r/"})
		e.newConn = func(context.Context, string) (pgConn, error) { return rec, nil }

		if err := e.Rotate(ctx, ref, value); err != nil {
			// A non-nil error means the statement was NOT executed (the fake
			// conn never errors), so there is no sink output to check.
			return
		}
		if len(rec.stmts) != 1 {
			t.Fatalf("Rotate executed %d statements, want exactly 1: %q", len(rec.stmts), rec.stmts)
		}
		assertSafeAlterRole(t, rec.stmts[0], ref, value)
	})
}

// assertSafeAlterRole fails unless sql is exactly `ALTER ROLE <id> WITH PASSWORD
// <lit>` with <id> decoding to ref and <lit> decoding to value.
func assertSafeAlterRole(t *testing.T, sql, ref, value string) {
	t.Helper()
	const head = "ALTER ROLE "
	if !strings.HasPrefix(sql, head) {
		t.Fatalf("statement does not start with %q: %q", head, sql)
	}
	rest := sql[len(head):]
	id, rest, ok := parseQuotedIdent(rest)
	if !ok {
		t.Fatalf("identifier slot is not a well-formed double-quoted identifier: %q (ref=%q)", sql, ref)
	}
	if id != ref {
		t.Fatalf("identifier decoded to %q, want ref %q — ref escaped its quoted slot: %q", id, ref, sql)
	}
	const mid = " WITH PASSWORD "
	if !strings.HasPrefix(rest, mid) {
		t.Fatalf("expected %q after identifier, got %q (full: %q)", mid, rest, sql)
	}
	lit := rest[len(mid):]
	val, ok := parseEString(lit)
	if !ok {
		t.Fatalf("password slot is not a well-formed E'…' literal consuming the rest: %q (value=%q)", sql, value)
	}
	if val != value {
		t.Fatalf("password decoded to %q, want %q — value escaped its quoted slot: %q", val, value, sql)
	}
}

// parseQuotedIdent decodes a leading PostgreSQL double-quoted identifier
// ("" is an escaped "), returning the decoded value and the remainder after the
// closing quote.
func parseQuotedIdent(s string) (decoded, rest string, ok bool) {
	if len(s) == 0 || s[0] != '"' {
		return "", s, false
	}
	var b strings.Builder
	i := 1
	for i < len(s) {
		if s[i] == '"' {
			if i+1 < len(s) && s[i+1] == '"' { // "" -> literal "
				b.WriteByte('"')
				i += 2
				continue
			}
			return b.String(), s[i+1:], true // closing quote
		}
		b.WriteByte(s[i])
		i++
	}
	return "", s, false // unterminated
}

// parseEString decodes an E'…' literal (” -> ', \\ -> \) and requires it to
// consume the ENTIRE input (the statement ends with the literal).
func parseEString(s string) (decoded string, ok bool) {
	if !strings.HasPrefix(s, "E'") {
		return "", false
	}
	var b strings.Builder
	i := 2
	for i < len(s) {
		switch {
		case s[i] == '\\':
			if i+1 >= len(s) {
				return "", false // dangling backslash
			}
			b.WriteByte(s[i+1]) // \\ -> \, \' would be unusual but decode the next byte
			i += 2
		case s[i] == '\'':
			if i+1 < len(s) && s[i+1] == '\'' { // '' -> literal '
				b.WriteByte('\'')
				i += 2
				continue
			}
			// closing quote: must be the last byte
			return b.String(), i == len(s)-1
		default:
			b.WriteByte(s[i])
			i++
		}
	}
	return "", false // unterminated
}
