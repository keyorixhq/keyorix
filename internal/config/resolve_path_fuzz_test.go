package config

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// FuzzResolveConfigRelativePath drives resolveConfigRelativePath, the
// config-load function that anchors relative SQLite database paths to the
// config file's directory and blocks path-traversal via "..".  The dbPath
// argument comes from the operator-supplied storage.database.path YAML key
// (config.go's Load step).  A traversal escape would let the config silently
// resolve a path outside the intended directory.
//
// Oracles — all fatal (the code is in production and must hold today):
//
//	(a) NEVER-PANIC: resolveConfigRelativePath does not panic on any input.
//	(b) TRAVERSAL REJECTED: if the base part of dbPath (before '?') contains
//	    "..", the function must return an error.  It must never silently
//	    return a clean absolute path that crossed the traversal boundary.
//	(c) ABSOLUTE PASS-THROUGH: if dbPath is already absolute (starts with
//	    '/' on Unix), the returned path starts with the same absolute prefix
//	    (the base, before any '?' suffix, is not re-based).
//	(d) SPECIAL VALUES PASS-THROUGH: ":memory:" and any path containing
//	    "mode=memory" pass through unchanged with no error.
//	(e) SUCCESS IS ABSOLUTE: if the function returns no error and the path
//	    is not ":memory:" and does not contain "mode=memory" and is not
//	    empty, the returned path must be absolute.
//
// What this does NOT verify: that the resolved path is accessible or has
// correct permissions, nor that the '?' suffix is a valid SQLite pragma
// string.
func FuzzResolveConfigRelativePath(f *testing.F) {
	const baseDir = "/etc/keyorix"

	seeds := []string{
		"",
		":memory:",
		"keyorix.db",
		"data/keyorix.db",
		"../../etc/shadow",
		"../sibling/keyorix.db",
		"/absolute/path/keyorix.db",
		"./relative.db",
		"keyorix.db?_pragma=journal_mode(WAL)",
		"?mode=memory",
		":memory:?_pragma=busy_timeout(5000)",
		"some/path/db?mode=memory&cache=shared",
		"a/b/../c/keyorix.db",
		"../../../tmp/x.db",
		"db?mode=memory",
		"keyorix\x00.db",
		strings.Repeat("a/", 50) + "db",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, dbPath string) {
		if len(dbPath) > 4096 {
			return
		}

		// Oracle (a): never panics.
		var got string
		var err error
		fuzzutil.Guard(t.Fatalf, "resolveConfigRelativePath", func() {
			got, err = resolveConfigRelativePath(baseDir, dbPath)
		})

		// Oracle (d): special values pass through unchanged.
		if dbPath == ":memory:" {
			if err != nil || got != ":memory:" {
				t.Fatalf("resolveConfigRelativePath(%q, %q): want (%q, nil), got (%q, %v)", baseDir, dbPath, ":memory:", got, err)
			}
			return
		}
		if strings.Contains(dbPath, "mode=memory") {
			if err != nil || got != dbPath {
				t.Fatalf("resolveConfigRelativePath(%q, %q): mode=memory path, want (%q, nil), got (%q, %v)", baseDir, dbPath, dbPath, got, err)
			}
			return
		}
		if dbPath == "" {
			if err != nil || got != "" {
				t.Fatalf("resolveConfigRelativePath(%q, %q): empty path, want (\"\", nil), got (%q, %v)", baseDir, dbPath, got, err)
			}
			return
		}

		// Extract base (before '?').
		base := dbPath
		if idx := strings.IndexByte(dbPath, '?'); idx != -1 {
			base = dbPath[:idx]
		}

		// Oracle (b): traversal via ".." in the base must be rejected.
		if !filepath.IsAbs(base) && strings.Contains(base, "..") {
			if err == nil {
				t.Fatalf("resolveConfigRelativePath(%q, %q): path with \"..\" should return error, got %q", baseDir, dbPath, got)
			}
			return
		}

		if err != nil {
			return // any other error is fine — the function may reject other patterns
		}

		// Oracle (c): already-absolute base is not re-based.
		if filepath.IsAbs(base) {
			suffix := ""
			if idx := strings.IndexByte(dbPath, '?'); idx != -1 {
				suffix = dbPath[idx:]
			}
			want := base + suffix
			if got != want {
				t.Fatalf("resolveConfigRelativePath(%q, %q): absolute path, want %q, got %q", baseDir, dbPath, want, got)
			}
			return
		}

		// Oracle (e): non-special, non-empty, no error → result is absolute.
		if !filepath.IsAbs(got) {
			t.Fatalf("resolveConfigRelativePath(%q, %q): no error but result %q is not absolute", baseDir, dbPath, got)
		}
	})
}
