package pgdsn

// shared_database_activity_guard_test.go — the guard for the class
// PG-TEST-ISOLATION-1 swept: a Postgres test that reads another package's
// backends. The nightly runs ./internal/core/... and ./internal/storage/...
// in parallel against ONE KEYORIX_TEST_PG_DSN database, and tests isolate by
// schema (pgIsolatedSchemaDSN, PGSearchPathDSN), which separates rows but not
// backends. pg_stat_activity and pg_locks list every backend of the server, so
// a count, a lock-wait gate, a snapshot age or a pg_terminate_backend over
// "this database" also sees (and can kill) a parallel package's sessions
// (AUDIT-LONGREADER-PG-1: a snapshot held by another package's test was
// reported as the audit walk's own).
//
// A query FROM/JOIN pg_stat_activity in a _test.go file must be scoped to the
// test's own backends by one of:
//   - application_name (tag the connections with WithApplicationName);
//   - one backend: pid = $1 / pid = ? / pid = pg_backend_pid(), or
//     $1 = ANY(pg_blocking_pids(pid));
//   - an advisory-lock key of its own, via a pg_locks query scoped by database
//     (the rule below), when the pg_stat_activity part is only a join on pid;
//   - a database of its own: datname = current_database() alone does NOT
//     count on a shared database, so it is accepted only in a file that creates
//     its database with IsolatedDatabase / MigratedDatabase / a *IsolatedDatabaseDSN
//     helper; or datname = $1 / ?, where the test passes the name of the
//     database it created (the guard cannot tell that name from the shared
//     database's, so this form is on the reviewer).
//
// A query FROM/JOIN pg_locks must be scoped to the test's database
// (current_database() / datname) or to one backend (pid = ...).
//
// What it recognizes: Go string literals in _test.go files under internal/,
// server/ and scripts/, with `"a" + "b"` concatenations folded. It does not see
// a query assembled with fmt.Sprintf from non-literal parts, held in a variable
// declared elsewhere in pieces, or kept in a non-test file; and "a file that
// isolates its database" is judged by the call names in that file, so a DSN
// handed in from another file is not seen (that file is flagged and needs an
// application_name filter, which is always correct).

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/guardrules"
)

var (
	fromActivity = regexp.MustCompile(`\b(from|join)\s+(pg_catalog\.)?pg_stat_activity\b`)
	fromLocks    = regexp.MustCompile(`\b(from|join)\s+(pg_catalog\.)?pg_locks\b`)
	// blockedBy: `$1 = ANY(pg_blocking_pids(pid))` names one blocker by parameter.
	blockedBy = regexp.MustCompile(`(\?|\$\d)\s*=\s*any\s*\(\s*pg_blocking_pids`)
	// namedDatabase: datname = $1 / ? — the test passes the name of the database
	// it created. The guard cannot tell that name from the shared database's.
	namedDatabase = regexp.MustCompile(`datname\s*=\s*(\?|\$\d)`)
)

type activityFinding struct{ pos, msg string }

// foldString returns the constant string value of a literal or a `+` chain of
// literals, and false for anything else.
func foldString(e ast.Expr) (string, bool) {
	switch e := e.(type) {
	case *ast.BasicLit:
		if e.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(e.Value)
		return s, err == nil
	case *ast.BinaryExpr:
		if e.Op != token.ADD {
			return "", false
		}
		l, ok := foldString(e.X)
		if !ok {
			return "", false
		}
		r, ok := foldString(e.Y)
		return l + r, ok
	case *ast.ParenExpr:
		return foldString(e.X)
	}
	return "", false
}

// activityQueryProblem returns why one query string reads database-wide
// backend state without scoping it to the test's own, or "".
func activityQueryProblem(q string, ownDatabase bool) string {
	low := strings.ToLower(q)
	usesLocks := fromLocks.MatchString(low)
	locksScoped := strings.Contains(low, "current_database()") || strings.Contains(low, "datname") || boundPid.MatchString(low)
	if usesLocks && !locksScoped {
		return "pg_locks query is not scoped to this test's database (database = (SELECT oid FROM pg_database WHERE datname = current_database())) or to one backend (pid = ...)"
	}
	if !fromActivity.MatchString(low) {
		return ""
	}
	switch {
	case strings.Contains(low, "application_name"), boundPid.MatchString(low), blockedBy.MatchString(low), namedDatabase.MatchString(low):
		return ""
	case usesLocks && locksScoped && strings.Contains(low, "'advisory'"):
		return "" // keyed on one advisory lock; the pg_stat_activity part is a join on its holder
	case ownDatabase && (strings.Contains(low, "current_database()") || strings.Contains(low, "datname")):
		return ""
	}
	return "pg_stat_activity query reads every backend of a database that parallel packages share: filter on application_name (pgdsn.WithApplicationName on the connections under test) or one pid; datname = current_database() is enough only in a file that creates its own database (pgdsn.IsolatedDatabase)"
}

// scanSharedDatabaseActivity applies the rules to one parsed test file.
func scanSharedDatabaseActivity(fset *token.FileSet, f *ast.File) []activityFinding {
	ownDatabase := false
	ast.Inspect(f, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok {
			name := ""
			switch fn := c.Fun.(type) {
			case *ast.Ident:
				name = fn.Name
			case *ast.SelectorExpr:
				name = fn.Sel.Name
			}
			if strings.Contains(name, "IsolatedDatabase") || strings.Contains(name, "MigratedDatabase") {
				ownDatabase = true
			}
		}
		return true
	})
	var out []activityFinding
	ast.Inspect(f, func(n ast.Node) bool {
		e, ok := n.(ast.Expr)
		if !ok {
			return true
		}
		s, ok := foldString(e)
		if !ok {
			return true
		}
		if msg := activityQueryProblem(s, ownDatabase); msg != "" {
			out = append(out, activityFinding{fset.Position(e.Pos()).String(), msg})
		}
		return false // a folded chain is judged as a whole, not per literal
	})
	return out
}

func TestSharedDatabaseActivityGuard(t *testing.T) {
	g := guardrules.Rollout(t)
	root := repoRoot(t)
	files := 0
	for _, top := range []string{"internal", "server", "scripts"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, "_test.go") {
				return nil
			}
			if b := filepath.Base(path); b == "shared_database_activity_guard_test.go" || b == "shared_database_lock_guard_test.go" {
				return nil // their calibration strings are the planted violations
			}
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			files++
			for _, fd := range scanSharedDatabaseActivity(fset, f) {
				rel, _ := filepath.Rel(root, fd.pos)
				g.Errorf("%s: %s", rel, fd.msg)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if files < 100 {
		t.Fatalf("scanned only %d test files: the walk is not covering the repository", files)
	}
}

// TestSharedDatabaseActivityGuard_Calibration: each rule fires on the shape
// that flaked (a datname-only count on a schema-isolated database) and stays
// quiet on the fixed one and on the forms that were already safe.
func TestSharedDatabaseActivityGuard_Calibration(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want int
	}{
		{"datname-only lock-wait count on a schema DSN (the coalescer test)", "package x\nfunc f() { dsn := pgIsolatedSchemaDSN(t, base); _ = dsn }\nvar q = `SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'`", 1},
		{"same count filtered on application_name", "package x\nvar q = `SELECT count(*) FROM pg_stat_activity WHERE application_name = ? AND wait_event_type = 'Lock'`", 0},
		{"datname-only count in a file with its own database", "package x\nfunc f() { dsn := pgIsolatedDatabaseDSN(t, base); _ = dsn }\nvar q = `SELECT count(*) FROM pg_stat_activity WHERE datname = current_database()`", 0},
		{"datname-only count, own database made by pgdsn.IsolatedDatabase", "package x\nfunc f() { _ = pgdsn.IsolatedDatabase(t, base, \"x\") }\nvar q = `SELECT count(*) FROM pg_stat_activity WHERE datname = current_database()`", 0},
		{"every other backend of the database is terminated, no tag", "package x\nvar q = `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = current_database() AND pid <> pg_backend_pid()`", 1},
		{"every other backend of a database the test names", "package x\nvar q = `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = ? AND pid <> pg_backend_pid()`", 0},
		{"one backend by pid", "package x\nvar q = `SELECT coalesce(query, '') FROM pg_stat_activity WHERE pid = ?`", 0},
		{"one blocker by parameter", "package x\nvar q = `SELECT count(*) FROM pg_stat_activity WHERE ? = ANY(pg_blocking_pids(pid))`", 0},
		{"a self-excluding pid is not a scope", "package x\nvar q = `SELECT count(*) FROM pg_stat_activity WHERE pid <> pg_backend_pid() AND backend_xmin IS NOT NULL`", 1},
		{"query split over two literals, unscoped", "package x\nvar q = \"SELECT count(*) FROM pg_stat_activity \" + \"WHERE wait_event = 'PgSleep'\"", 1},
		{"query split over two literals, tagged in the second", "package x\nvar q = \"SELECT count(*) FROM pg_stat_activity \" + \"WHERE application_name = $1\"", 0},
		{"advisory-key join on the holder", "package x\nvar q = `SELECT a.state FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid WHERE l.locktype = 'advisory' AND l.database = (SELECT oid FROM pg_database WHERE datname = current_database()) AND l.classid = ?`", 0},
		{"pg_locks join on pid, not scoped to a database", "package x\nvar q = `SELECT a.state FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid WHERE l.locktype = 'relation' AND l.relation = ?`", 1},
		{"pg_locks of any kind, unscoped", "package x\nvar q = `SELECT mode FROM pg_locks WHERE relation = 'x'::regclass`", 1},
		{"a log message that names the view is not a query", "package x\nvar m = \"pg_stat_activity: %v\"", 0},
	}
	for _, c := range cases {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "x_test.go", c.src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := len(scanSharedDatabaseActivity(fset, f)); got != c.want {
			t.Errorf("%s: %d findings, want %d", c.name, got, c.want)
		}
	}
}
