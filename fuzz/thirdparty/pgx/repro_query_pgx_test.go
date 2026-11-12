package pgxfuzz

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// Minimal, deterministic reproducers for the pgx/v5 v5.11.0 defects found by
// FuzzPgxHostileQuery. Each replays 3 times and asserts the panic (so it stays
// green while the library bug exists and goes red the day pgx fixes it, at
// which point the entry in knownPgxPanicSites must be removed too).

// shortRowScript: RowDescription declaring two text columns, then a DataRow
// carrying only one value. A hostile server needs 2 messages.
func shortRowScript() []byte {
	return cat(
		encMsg('T', rowDescription(fieldDesc{"a", oidText, 0}, fieldDesc{"b", oidText, 0})),
		encMsg('D', dataRow([]byte("x"))),
		encMsg('C', cstr("SELECT 1")), encMsg('Z', readyForQuery()), encClose())
}

// longRowScript: one declared column, DataRow carrying two values.
func longRowScript() []byte {
	return cat(
		encMsg('T', rowDescription(fieldDesc{"a", oidText, 0})),
		encMsg('D', dataRow([]byte("x"), []byte("y"))),
		encMsg('C', cstr("SELECT 1")), encMsg('Z', readyForQuery()), encClose())
}

// recoverStack runs fn and returns the recovered panic value and stack.
func recoverStack(fn func()) (val any, stack string) {
	defer func() {
		if r := recover(); r != nil {
			val, stack = r, string(debug.Stack())
		}
	}()
	fn()
	return nil, ""
}

// PGX-1: (*baseRows).Values indexes rows.values[i] for every field
// description without checking that the DataRow carried that many values.
// Scan and ScanRow DO check ("number of field descriptions must equal number of
// values", rows.go:262/394); Values does not (rows.go:321-322). The green
// control below shows Scan on the identical exchange returns that error.
func TestPgxValues_ShortDataRow_Reproducer(t *testing.T) {
	for i := range 3 {
		in := append([]byte{byte(opSimpleQuery)}, shortRowScript()...)
		val, stack := recoverStack(func() { runHostileQuery(t, in) })
		if val == nil {
			t.Fatalf("replay %d: expected panic in (*baseRows).Values; pgx may have fixed PGX-1 (remove it from knownPgxPanicSites)", i)
		}
		if !strings.Contains(fmt.Sprint(val), "index out of range") || !strings.Contains(stack, "(*baseRows).Values") {
			t.Fatalf("replay %d: unexpected panic %v\n%s", i, val, stack)
		}
	}
	// Green control: Scan on the same exchange reports the mismatch as an error.
	in := append([]byte{byte(opSimpleQuery)}, shortRowScript()...)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen on loopback: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go serveQuery(ln, append(handshakeOK(), buildScript(in[1:])...))
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, fmt.Sprintf("postgres://u:%s@%s/db?sslmode=disable", canaryPassword, ln.Addr()))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	var a, b string
	err = conn.QueryRow(ctx, "select", pgx.QueryExecModeSimpleProtocol).Scan(&a, &b)
	if err == nil || !strings.Contains(err.Error(), "number of field descriptions must equal number of values") {
		t.Fatalf("green control: Scan should reject the short row, got %v", err)
	}
}

// Refuted hypothesis, pinned so it stays refuted: reading stdlib (*Rows).Next
// (stdlib/sql.go:896-899) suggested that a DataRow with MORE values than
// declared columns would index past database/sql's dest slice. Run against the
// real adapter (Go 1.27.3) it does not panic and the first column decodes;
// why the read of the code was wrong was not established (time). This
// test fails if the over-long row ever starts panicking or stops decoding.
func TestPgxStdlib_LongDataRow_NoPanic(t *testing.T) {
	for i := range 3 {
		var got string
		val, stack := recoverStack(func() { got = runStdlibQuery(t, longRowScript()) })
		if val != nil {
			t.Fatalf("replay %d: over-long DataRow now panics in the stdlib adapter: %v\n%s", i, val, stack)
		}
		if got != "x" {
			t.Fatalf("replay %d: got %q", i, got)
		}
	}
	// Green control: a well-formed row through the same path decodes.
	if got := runStdlibQuery(t, cat(
		encMsg('T', rowDescription(fieldDesc{"a", oidText, 0})), encMsg('D', dataRow([]byte("ok-row"))),
		encMsg('C', cstr("SELECT 1")), encMsg('Z', readyForQuery()), encClose())); got != "ok-row" {
		t.Fatalf("green control: got %q", got)
	}
}

// runStdlibQuery drives database/sql over pgx's stdlib adapter (simple
// protocol, one connection) against the hostile script and returns the first
// column of the first row.
func runStdlibQuery(t *testing.T, script []byte) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen on loopback: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go serveQuery(ln, append(handshakeOK(), buildScript(script)...))
	cfg, err := pgx.ParseConfig(fmt.Sprintf("postgres://u:%s@%s/db?sslmode=disable", canaryPassword, ln.Addr()))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	cfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	db := stdlib.OpenDB(*cfg)
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	rows, err := db.QueryContext(ctx, "select a from t")
	if err != nil {
		return "err:" + err.Error()
	}
	defer func() { _ = rows.Close() }()
	var s sql.NullString
	if rows.Next() {
		_ = rows.Scan(&s)
	}
	return s.String
}

// TestPgxQuery_AllowlistStillSurfacesNovelPanics: the allowlist swallows the
// real PGX-1 stack (green) but not a panic raised from any other site (red), so
// a third, unknown panic site would still fail the fuzz run.
func TestPgxQuery_AllowlistStillSurfacesNovelPanics(t *testing.T) {
	in := append([]byte{byte(opSimpleQuery)}, shortRowScript()...)
	val, stack := recoverStack(func() { runHostileQuery(t, in) })
	if val == nil {
		t.Fatal("PGX-1 reproducer did not panic")
	}
	if msg := classifyPanic(val, stack); msg != "" {
		t.Fatalf("known PGX-1 stack not recognised: %s", msg)
	}
	var idx []int
	val, stack = recoverStack(func() { _ = idx[len(in)] })
	if val == nil {
		t.Fatal("planted panic did not fire")
	}
	if classifyPanic(val, stack) == "" {
		t.Fatal("RED expected: a panic from an unlisted site was swallowed by the allowlist")
	}
}
