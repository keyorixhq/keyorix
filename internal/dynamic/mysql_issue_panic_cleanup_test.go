package dynamic

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"log"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// #4378 review: a client-library panic after MySQL CREATE USER ran must not leave an
// unleased kx_dyn_* account on the target. These tests drive Issue through New (so
// through Contain, the production path) against a fake driver that panics on a chosen
// statement, and check the account is dropped and the caller still gets the typed,
// panic-text-free *EngineClientPanicError.

const mysqlPanicDSN = "admin:hunter2@tcp(db.internal:3306)/"

// execRecorder is a database/sql driver whose ExecContext records every statement
// and panics on the first one containing panicOn (and on DROP when dropPanics).
type execRecorder struct {
	mu         sync.Mutex
	stmts      []string
	panicOn    string
	dropPanics bool
}

func (r *execRecorder) Connect(context.Context) (driver.Conn, error) { return &recConn{r: r}, nil }
func (r *execRecorder) Driver() driver.Driver                        { return recDriver{} }

func (r *execRecorder) statements() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.stmts...)
}

type recDriver struct{}

func (recDriver) Open(string) (driver.Conn, error) { return nil, errors.New("use the connector") }

type recConn struct{ r *execRecorder }

func (c *recConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("not supported") }
func (c *recConn) Close() error                        { return nil }
func (c *recConn) Begin() (driver.Tx, error)           { return nil, errors.New("not supported") }

func (c *recConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	c.r.mu.Lock()
	c.r.stmts = append(c.r.stmts, query)
	panicOn, dropPanics := c.r.panicOn, c.r.dropPanics
	c.r.mu.Unlock()
	if strings.HasPrefix(query, "DROP USER") && dropPanics {
		panic("drop also failed")
	}
	if panicOn != "" && strings.Contains(query, panicOn) {
		panic("malformed OK packet from " + mysqlPanicDSN)
	}
	return driver.RowsAffected(0), nil
}

// useRecorder points Issue's admin connection at rec. Not parallel-safe (package var).
func useRecorder(t *testing.T, rec *execRecorder) {
	t.Helper()
	orig := openMySQLAdmin
	t.Cleanup(func() { openMySQLAdmin = orig })
	openMySQLAdmin = func(context.Context, string, bool) (*sql.DB, error) {
		return sql.OpenDB(rec), nil
	}
}

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return &buf
}

func createdUser(t *testing.T, stmts []string) string {
	t.Helper()
	for _, s := range stmts {
		if rest, ok := strings.CutPrefix(s, "CREATE USER '"); ok {
			user, _, _ := strings.Cut(rest, "'")
			return user
		}
	}
	t.Fatalf("no CREATE USER among %q", stmts)
	return ""
}

func issueContained(t *testing.T, template string) error {
	t.Helper()
	eng, err := New("mysql", true, true)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var issueErr error
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic reached the caller of the contained engine: %v", r)
			}
		}()
		_, _, issueErr = eng.Issue(context.Background(), mysqlPanicDSN, template, time.Minute)
	}()
	return issueErr
}

func assertTypedPanicError(t *testing.T, err error) {
	t.Helper()
	var pe *EngineClientPanicError
	if !errors.As(err, &pe) || pe.Name != "mysql" || pe.Op != "Issue" {
		t.Fatalf("want *EngineClientPanicError{mysql, Issue}, got %#v", err)
	}
	for _, leak := range []string{"hunter2", "db.internal", "malformed"} {
		if strings.Contains(err.Error(), leak) {
			t.Fatalf("error leaks %q: %v", leak, err)
		}
	}
}

func assertDropped(t *testing.T, stmts []string) {
	t.Helper()
	want := "DROP USER IF EXISTS '" + createdUser(t, stmts) + "'@'%'"
	for _, s := range stmts {
		if s == want {
			return
		}
	}
	t.Fatalf("account not dropped after the panic; statements: %q", stmts)
}

func TestMySQLIssue_PanicInGrantDropsCreatedUser(t *testing.T) {
	rec := &execRecorder{panicOn: "GRANT"}
	useRecorder(t, rec)
	logs := captureLog(t)

	err := issueContained(t, "GRANT SELECT ON app.* TO {{name}}")
	assertTypedPanicError(t, err)
	assertDropped(t, rec.statements())

	out := logs.String()
	if !strings.Contains(out, "malformed OK packet") {
		t.Errorf("the original panic must still be logged by Contain:\n%s", out)
	}
	if strings.Contains(out, "hunter2") {
		t.Errorf("log carries the admin password (re-panic bypassed the redacting wrapper?):\n%s", out)
	}
}

// A panic while reading CREATE USER's own reply can follow a CREATE the server ran.
func TestMySQLIssue_PanicInCreateReplyDropsUser(t *testing.T) {
	rec := &execRecorder{panicOn: "CREATE USER"}
	useRecorder(t, rec)
	captureLog(t)

	assertTypedPanicError(t, issueContained(t, ""))
	assertDropped(t, rec.statements())
}

// The cleanup's own DROP can panic on the same broken connection; the caller still gets
// the typed error for the original panic, and the original is what gets logged.
func TestMySQLIssue_PanicInCleanupKeepsOriginalPanic(t *testing.T) {
	rec := &execRecorder{panicOn: "GRANT", dropPanics: true}
	useRecorder(t, rec)
	logs := captureLog(t)

	assertTypedPanicError(t, issueContained(t, "GRANT SELECT ON app.* TO {{name}}"))
	out := logs.String()
	if !strings.Contains(out, "malformed OK packet") || strings.Contains(out, "drop also failed") {
		t.Errorf("want the original panic logged, not the cleanup's:\n%s", out)
	}
}

// Green direction: without a panic the cleanup never drops the account it just issued.
func TestMySQLIssue_NoPanicNoDrop(t *testing.T) {
	rec := &execRecorder{}
	useRecorder(t, rec)

	eng, err := New("mysql", true, true)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, role, err := eng.Issue(context.Background(), mysqlPanicDSN, "GRANT SELECT ON app.* TO {{name}}", time.Minute)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	for _, s := range rec.statements() {
		if strings.HasPrefix(s, "DROP USER") {
			t.Fatalf("issued account %s dropped without a panic: %q", role, rec.statements())
		}
	}
}
