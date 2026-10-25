package journeys

// No build tag on purpose: the journeys (//go:build e2e) call sqliteCLI, and the guard and the
// lock test below need no server or binaries, so they run in the ordinary `go test`.

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// sqliteCLIBusyTimeoutMillis is how long a journey's sqlite3 process waits for the write lock.
// It equals internal/storage's sqliteBusyTimeoutMillis: the busy timeout the server documents
// for a second process writing its database.
const sqliteCLIBusyTimeoutMillis = 10000

// sqliteCLI is the only way a journey runs the sqlite3 CLI. Several journeys write the LIVE
// server's database (a trigger that makes the audit log refuse rows), and the server holds the
// write lock for every audit row, session and job tick it writes. The sqlite3 CLI's own busy
// timeout is 0: a statement that meets the server's lock fails at once with "database is
// locked (5)" (#3683: TestJourney_BreakGlassDegradedWhileAuditDown, 3 PRs in 72 h). With
// .timeout it waits for the server's transaction to finish, the same rule the server's own
// connections follow.
func sqliteCLI(dbPath, stmt string) *exec.Cmd {
	return exec.Command("sqlite3", "-cmd", fmt.Sprintf(".timeout %d", sqliteCLIBusyTimeoutMillis), dbPath, stmt) // #nosec G204 -- callers pass their own tempdir DB path and a fixed or int-formatted statement
}

// rawSQLiteCLI matches an exec.Command that starts sqlite3 directly.
var rawSQLiteCLI = regexp.MustCompile(`exec\.Command(Context)?\(\s*(ctx\s*,\s*)?"sqlite3"`)

// TestJourneysRunSQLiteOnlyThroughHelper fails when a journey starts sqlite3 itself instead of
// through sqliteCLI, so a new journey cannot bring back the zero busy timeout.
//
// What it does NOT cover: a binary name built at run time ("sqlite" + "3") or held in a
// variable, and sqlite3 started from a shell script.
func TestJourneysRunSQLiteOnlyThroughHelper(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	const self = "sqlite_cli_test.go"
	scanned := 0
	var bad []string
	for _, f := range files {
		if f == self {
			continue
		}
		raw, err := os.ReadFile(f) // #nosec G304 -- a file of this package's own directory
		if err != nil {
			t.Fatal(err)
		}
		scanned++
		for i, line := range strings.Split(string(raw), "\n") {
			if rawSQLiteCLI.MatchString(line) {
				bad = append(bad, fmt.Sprintf("%s:%d: %s", f, i+1, strings.TrimSpace(line)))
			}
		}
	}
	if scanned < 20 {
		t.Fatalf("scanned only %d journey files: the guard is looking in the wrong directory", scanned)
	}
	if len(bad) > 0 {
		t.Fatalf("run sqlite3 through sqliteCLI (sqlite_cli_test.go), which waits for the server's write lock; "+
			"a bare sqlite3 fails at once with \"database is locked\" while the server writes:\n  %s",
			strings.Join(bad, "\n  "))
	}
}

func TestRawSQLiteCLIPattern(t *testing.T) {
	for _, s := range []string{
		`out, err := exec.Command("sqlite3", dbPath, stmt).CombinedOutput()`,
		`cmd := exec.Command( "sqlite3", dbPath, "PRAGMA wal_checkpoint(TRUNCATE);")`,
		`exec.CommandContext(ctx, "sqlite3", dbPath, stmt)`,
	} {
		if !rawSQLiteCLI.MatchString(s) {
			t.Errorf("guard misses %s", s)
		}
	}
	for _, s := range []string{
		`out, err := sqliteCLI(dbPath, stmt).CombinedOutput()`,
		`// sqlite3 on the runner's PATH`,
		`exec.Command(s.Binary, "admin", "verify-audit")`,
	} {
		if rawSQLiteCLI.MatchString(s) {
			t.Errorf("guard flags %s", s)
		}
	}
}

// TestSQLiteCLI_WaitsForAnotherWritersLock reproduces #3683 without a server: a second sqlite3
// process holds the write lock for about a second, the way the server does while it writes an
// audit row. A bare sqlite3 fails with "database is locked"; sqliteCLI waits and succeeds.
func TestSQLiteCLI_WaitsForAnotherWritersLock(t *testing.T) {
	if _, err := exec.LookPath("sqlite3"); err != nil {
		t.Skip("sqlite3 is not on PATH (the e2e journeys need it; this unit test cannot run without it)")
	}
	dbPath := filepath.Join(t.TempDir(), "lock.db")
	if out, err := sqliteCLI(dbPath, "PRAGMA journal_mode=WAL; CREATE TABLE t (v INTEGER);").CombinedOutput(); err != nil {
		t.Fatalf("create db: %v\n%s", err, out)
	}

	// holdLock starts a writer that takes the write lock, keeps it about a second and commits.
	// It prints "locked" once the lock is held, so the caller knows when to race it.
	holdLock := func(t *testing.T) *exec.Cmd {
		t.Helper()
		h := exec.Command("sqlite3", dbPath) // #nosec G204 -- this test's own tempdir DB path
		h.Stdin = strings.NewReader("BEGIN IMMEDIATE;\nINSERT INTO t VALUES (1);\n.print locked\n.shell sleep 1\nCOMMIT;\n")
		stdout, err := h.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := h.Start(); err != nil {
			t.Fatal(err)
		}
		r := bufio.NewReader(stdout)
		if line, err := r.ReadString('\n'); err != nil || strings.TrimSpace(line) != "locked" {
			_ = h.Process.Kill()
			t.Fatalf("lock holder did not report the lock: %q, %v", line, err)
		}
		go func() { _, _ = io.Copy(io.Discard, r) }()
		return h
	}
	const ddl = "CREATE TRIGGER j_lock_test BEFORE INSERT ON t BEGIN SELECT 1; END; DROP TRIGGER j_lock_test;"

	t.Run("bare sqlite3 fails at once", func(t *testing.T) {
		h := holdLock(t)
		out, err := exec.Command("sqlite3", dbPath, ddl).CombinedOutput() // #nosec G204 -- this test's own tempdir DB path; the bare form is what this subtest demonstrates
		_ = h.Wait()
		if err == nil || !strings.Contains(string(out), "database is locked") {
			t.Fatalf("want \"database is locked\" from a bare sqlite3 while another writer holds the lock, got err=%v:\n%s", err, out)
		}
	})
	t.Run("sqliteCLI waits for the lock", func(t *testing.T) {
		h := holdLock(t)
		start := time.Now()
		out, err := sqliteCLI(dbPath, ddl).CombinedOutput()
		_ = h.Wait()
		if err != nil {
			t.Fatalf("sqliteCLI must wait for the other writer's lock: %v\n%s", err, out)
		}
		t.Logf("waited %s for the other writer", time.Since(start).Round(10*time.Millisecond))
	})
}
