package sqlitepath

// LIB-FUZZ-2 target 2b: DatabaseFile against the SQLite that really opens the path.
//
// Inventory. storage.database.path is operator-supplied configuration (trusted
// input), but it is also a free-form string the driver parses as a SQLite URI,
// and DatabaseFile re-implements that parse (sqlite3ParseUri plus modernc.org/
// sqlite's own query cut) so that the server lock sidecar, the database file's
// 0600 permission tightening and the migration lock all land on the file SQLite
// opens. A divergence is not a crash but a silent loss of those protections: the
// lock or the chmod hits a different file than the database (this already
// happened once with "file:" URIs, see the DatabaseFile doc).
//
// Differential oracle, with the real driver as the reference: open the string
// with modernc.org/sqlite and read the main database's file out of
// PRAGMA database_list. Then:
//   - DatabaseFile says a file  <=> SQLite opened a file (not memory or temp);
//   - when both say a file, they name the same one.
//
// Safety: SQLite really creates the file, so every input is confined. The fuzzed
// tail is appended after a fixed absolute directory that sits 24 levels inside a
// private temp tree and is capped at 64 bytes, so even a tail of nothing but
// "../" cannot climb out (21 levels at most); a tail naming a "_pragma" or a
// "vfs" is skipped because those are driver/SQLite switches that act beyond the
// path. Files an input created are removed after each run.

import (
	"database/sql"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// pathSpelling joins one of the DSN spellings to base and tail.
func pathSpelling(kind uint8, base, tail string) string {
	switch kind % 4 {
	case 0:
		return base + "/" + tail
	case 1:
		return "file:" + base + "/" + tail
	case 2:
		return "file://" + base + "/" + tail
	default:
		return "file://localhost" + base + "/" + tail
	}
}

func skipTail(tail string) bool {
	// A raw NUL byte is a known divergence, not a target: SQLite (C strings)
	// stops the path there, DatabaseFile keeps the bytes after it (it only ends
	// the path on a decoded %00). Go's file calls reject a path containing NUL, so
	// the lock/permission consumers fail with EINVAL instead of touching another
	// file, and the string can only come from the operator's own config.
	if len(tail) > 64 || strings.ContainsRune(tail, 0) {
		return true
	}
	dec, err := url.QueryUnescape(tail)
	if err != nil {
		dec = tail
	}
	for _, s := range []string{tail, dec, strings.ToLower(dec)} {
		l := strings.ToLower(s)
		if strings.Contains(l, "pragma") || strings.Contains(l, "vfs") {
			return true
		}
	}
	return false
}

func treeFiles(tb testing.TB, root string) map[string]bool {
	tb.Helper()
	out := map[string]bool{}
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			out[p] = true
		}
		return nil
	})
	if err != nil {
		tb.Fatal(err)
	}
	return out
}

// sqliteMainFile opens dsn with the real driver and returns the main database's
// file ("" for an in-memory or temporary database). ok is false when SQLite
// refused to open it, which the oracle cannot judge.
func sqliteMainFile(dsn string) (file string, ok bool) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return "", false
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)
	rows, err := db.Query(`PRAGMA database_list`)
	if err != nil {
		return "", false
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var seq int
		var name, f string
		if err := rows.Scan(&seq, &name, &f); err != nil {
			return "", false
		}
		if name == "main" {
			return f, true
		}
	}
	return "", false
}

// checkDatabaseFileAgrees is the oracle: realBase is base with symlinks
// resolved (SQLite reports resolved paths, t.TempDir() may sit behind one).
func checkDatabaseFileAgrees(dsn, base, realBase, opened string) string {
	p, isReal := DatabaseFile(dsn)
	switch {
	case isReal && opened == "":
		return "DatabaseFile names " + p + " but SQLite opened an in-memory or temporary database"
	case !isReal && opened != "":
		return "DatabaseFile says there is no file but SQLite opened " + opened
	case !isReal:
		return ""
	}
	want := filepath.Clean(p)
	if rest, ok := strings.CutPrefix(want, base); ok {
		want = realBase + rest
	}
	if want != filepath.Clean(opened) {
		return "DatabaseFile names " + p + " but SQLite opened " + opened
	}
	return ""
}

func FuzzDatabaseFileMatchesSQLite(f *testing.F) {
	root := f.TempDir()
	base := root
	for range 24 {
		base = filepath.Join(base, "d")
	}
	if err := os.MkdirAll(base, 0o700); err != nil {
		f.Fatal(err)
	}
	realBase, err := filepath.EvalSymlinks(base)
	if err != nil {
		f.Fatal(err)
	}
	for _, kind := range []uint8{0, 1, 2, 3} {
		for _, tail := range []string{
			"a.db", "a b.db", "a%20b.db", "100%/x", "a.db%00junk", "a.db?_busy_timeout=5000", "a.db?mode=memory",
			"a.db?_journal_mode=memory", "a.db?mode=memory&mode=rwc", "a.db?mode=rwc&mode=memory", "a.db#f?mode=memory",
			"?x.db", "#x.db", "a.db?xmode=memory", "a.db?mode%3dmemory", "a.db?mo%64e=memory", "a.db?mode=mem%6fry",
			"a.db?mode=memory&mode%00x=rwc", "a.db?mode=memory#", "%2e%2e/a.db", ":memory:",
		} {
			f.Add(kind, tail)
		}
	}
	f.Fuzz(func(t *testing.T, kind uint8, tail string) {
		if skipTail(tail) {
			t.Skip()
		}
		dsn := pathSpelling(kind, base, tail)
		before := treeFiles(t, root)
		defer func() {
			for p := range treeFiles(t, root) {
				if !before[p] {
					_ = os.Remove(p)
				}
			}
		}()
		var (
			opened string
			ok     bool
		)
		fuzzutil.Guard(t.Fatalf, "sqlite open", func() { opened, ok = sqliteMainFile(dsn) })
		if !ok {
			return
		}
		if msg := checkDatabaseFileAgrees(dsn, base, realBase, opened); msg != "" {
			t.Fatalf("%s\n  dsn: %q", msg, dsn)
		}
	})
}

// TestDatabaseFileOracle_RedProof: the oracle names each planted disagreement,
// and agrees on the plain, URI and in-memory spellings.
func TestDatabaseFileOracle_RedProof(t *testing.T) {
	base := filepath.Join(t.TempDir(), "d")
	if err := os.MkdirAll(base, 0o700); err != nil {
		t.Fatal(err)
	}
	realBase, err := filepath.EvalSymlinks(base)
	if err != nil {
		t.Fatal(err)
	}
	agree := func(dsn string) string {
		opened, ok := sqliteMainFile(dsn)
		if !ok {
			t.Fatalf("SQLite refused %q", dsn)
		}
		return checkDatabaseFileAgrees(dsn, base, realBase, opened)
	}
	for _, dsn := range []string{
		pathSpelling(0, base, "a.db"), pathSpelling(1, base, "a%20b.db"), pathSpelling(2, base, "c.db?mode=memory"),
		pathSpelling(3, base, "e.db#frag"), pathSpelling(1, base, "g.db%00junk"),
	} {
		if msg := agree(dsn); msg != "" {
			t.Errorf("oracle disagrees on a correct spelling %q: %s", dsn, msg)
		}
	}
	// Planted resolver faults: answer for a different file or the wrong memory-ness.
	file := filepath.Join(realBase, "a.db")
	for name, c := range map[string]struct{ dsn, opened string }{
		"resolver says memory, SQLite opened a file": {"file:" + base + "/a.db?mode=memory", file},
		"resolver says file, SQLite opened memory":   {pathSpelling(0, base, "a.db"), ""},
		"resolver names another file":                {pathSpelling(0, base, "a.db"), filepath.Join(realBase, "b.db")},
	} {
		if checkDatabaseFileAgrees(c.dsn, base, realBase, c.opened) == "" {
			t.Errorf("oracle missed planted disagreement: %s", name)
		}
	}
}
