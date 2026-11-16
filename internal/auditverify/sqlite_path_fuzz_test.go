package auditverify

// LIB-FUZZ-2 target 2c: the path handed to OpenSQLiteReadOnly.
//
// Inventory. `verify-audit --sqlite <path>` takes the path from the command line
// and builds the DSN "file:" + path + "?mode=ro". The path is the operator's, but
// it names an audit artifact whose file name can be anything the filesystem
// allows (an exported "a?b.db", "c#d.db", "e%41f.db"). Before sqliteURIPath, a
// "?" in the name became the query and dropped mode=ro, so the verifier opened a
// different file read-write (db_uri_path_test.go pins five such names). This
// target generalises that to any file name.
//
// Oracle, with decoys: for a file name NAME the harness creates NAME itself plus
// every file SQLite's URI parser could mistake it for (the name cut at each "?",
// "#" or "%", and the name with its %HH escapes decoded). Whatever
// OpenSQLiteReadOnly opens must be NAME (PRAGMA database_list), it must not have
// created or changed any file, and the connection must be read-only: a CREATE
// TABLE through it is refused (mode=ro reached SQLite, whatever the name).

import (
	"database/sql"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

func validBaseName(s string) bool {
	return s != "" && s != "." && s != ".." && len(s) <= 100 && utf8.ValidString(s) &&
		!strings.ContainsAny(s, "/\x00") && !strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

// uriDecoys returns the file names a URI-parsing mistake could open instead of name.
func uriDecoys(name string) []string {
	var out []string
	for i := 1; i < len(name); i++ {
		if strings.IndexByte("?#%", name[i]) >= 0 {
			out = append(out, name[:i])
		}
	}
	var b strings.Builder
	for i := 0; i < len(name); i++ {
		if name[i] == '%' && i+2 < len(name) {
			if v, err := strconv.ParseUint(name[i+1:i+3], 16, 8); err == nil && v != 0 {
				b.WriteByte(byte(v))
				i += 2
				continue
			}
		}
		b.WriteByte(name[i])
	}
	return append(out, b.String())
}

// acceptsWrite reports whether a CREATE TABLE through db succeeds. The probe
// runs before the directory snapshot, so a write that did land on disk is also
// caught there.
func acceptsWrite(db *sql.DB) bool {
	_, err := db.Exec(`CREATE TABLE keyorix_fuzz_ro_probe (x INTEGER)`)
	return err == nil
}

// openedFile returns the main database file OpenSQLiteReadOnly's connection has.
func openedFile(db *DB) (string, error) {
	rows, err := db.sql.Query(`PRAGMA database_list`)
	if err != nil {
		return "", err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var seq int
		var name, file string
		if err := rows.Scan(&seq, &name, &file); err != nil {
			return "", err
		}
		if name == "main" {
			return file, nil
		}
	}
	return "", rows.Err()
}

func FuzzOpenSQLiteReadOnlyPath(f *testing.F) {
	content := buildSmallAuditDB(f, 3, nil)
	for _, n := range []string{"a.db", "a?b.db", "c#d.db", "e%41f.db", "g.db?_pragma=journal_mode(delete)&x=", "h.db?mode=rwc",
		"%", "%%", "%2", "?", "#", "a?mode=memory", "x%3fy", "y%00z", "p%3Fq?r", "file:x.db", "a b.db", "a;b", "é.db", "a&b=c.db"} {
		f.Add(n)
	}
	f.Fuzz(func(t *testing.T, name string) {
		if !validBaseName(name) {
			t.Skip()
		}
		dir := t.TempDir()
		write := func(n string) {
			if err := os.WriteFile(filepath.Join(dir, n), content, 0o600); err != nil && !os.IsExist(err) {
				t.Skip() // the filesystem refuses this name: nothing to judge
			}
		}
		write(name)
		for _, d := range uriDecoys(name) {
			if validBaseName(d) {
				write(d)
			}
		}
		before := dirSnapshot(t, dir)
		var (
			opened   string
			writable bool
			err      error
		)
		fuzzutil.Guard(t.Fatalf, "OpenSQLiteReadOnly(path)", func() {
			db, e := OpenSQLiteReadOnly(filepath.Join(dir, name))
			if e != nil {
				err = e
				return
			}
			defer func() { _ = db.Close() }()
			if opened, err = openedFile(db); err == nil {
				writable = acceptsWrite(db.sql)
			}
		})
		if after := dirSnapshot(t, dir); !equalSnapshots(before, after) {
			t.Fatalf("opening %q read-only changed the directory", name)
		}
		if err != nil {
			return
		}
		want, rerr := filepath.EvalSymlinks(filepath.Join(dir, name))
		if rerr != nil {
			t.Fatal(rerr)
		}
		if got, _ := filepath.EvalSymlinks(opened); got != want {
			t.Fatalf("OpenSQLiteReadOnly(%q) opened %q, not the named file", name, opened)
		}
		if writable {
			t.Fatalf("OpenSQLiteReadOnly(%q) returned a connection that accepts writes", name)
		}
	})
}

func equalSnapshots(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}

// TestOpenSQLiteReadOnlyPathOracle_RedProof: the decoy oracle fires on the very
// defect sqliteURIPath exists to prevent. A DSN built WITHOUT the escaping opens a
// decoy for names with "?" or "#" (the pre-fix behaviour), and the oracle's
// comparison names it.
func TestOpenSQLiteReadOnlyPathOracle_RedProof(t *testing.T) {
	content := buildSmallAuditDB(t, 3, nil)
	for _, name := range []string{"a?b.db", "c#d.db"} {
		dir := t.TempDir()
		for _, n := range append([]string{name}, uriDecoys(name)...) {
			if err := os.WriteFile(filepath.Join(dir, n), content, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		// Planted fault: the unescaped DSN the old code used.
		unescaped := &DB{}
		var err error
		unescaped.sql, err = sqlOpenForRedProof("file:" + filepath.Join(dir, name) + "?mode=ro")
		if err != nil {
			t.Fatal(err)
		}
		got, err := openedFile(unescaped)
		if err != nil {
			t.Fatal(err)
		}
		// The dropped mode=ro is visible to the write probe too.
		if !acceptsWrite(unescaped.sql) {
			t.Errorf("planted unescaped DSN for %q refused a write; the read-only probe cannot see this fault", name)
		}
		_ = unescaped.Close()
		want, _ := filepath.EvalSymlinks(filepath.Join(dir, name))
		if g, _ := filepath.EvalSymlinks(got); g == want {
			t.Errorf("planted unescaped DSN for %q still opened the named file; the oracle cannot see this fault", name)
		}
		// And the real function opens the named file.
		db, err := OpenSQLiteReadOnly(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		got, err = openedFile(db)
		if err != nil {
			t.Fatal(err)
		}
		if acceptsWrite(db.sql) {
			t.Errorf("OpenSQLiteReadOnly(%q) accepted a write", name)
		}
		_ = db.Close()
		if g, _ := filepath.EvalSymlinks(got); g != want {
			t.Errorf("OpenSQLiteReadOnly(%q) opened %q", name, got)
		}
	}
}

// sqlOpenForRedProof opens a raw DSN with the driver, bypassing sqliteURIPath.
func sqlOpenForRedProof(dsn string) (*sql.DB, error) { return sql.Open("sqlite", dsn) }
