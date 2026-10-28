// Package sqlitepath resolves a SQLite storage.database.path value to the file
// SQLite opens. It has no dependencies so that both internal/serverguard (the
// server lock sidecar) and internal/storage (the database file's permissions
// and the migration lock) use the one resolver.
package sqlitepath

import (
	"net/url"
	"path/filepath"
	"strings"
)

// DatabaseFile resolves a storage.database.path value to the file
// SQLite opens, and reports whether there is one at all. A SQLite URI filename
// ("file:/data/secrets.db", "file:///...", "file://localhost/...",
// percent-encoded, with a query or fragment) resolves to the same path as its
// plain spelling; a query (DSN parameters) is never part of the path. Only
// a "file:" URI's query marks a database in-memory ("mode=memory"; a directory
// named "mode=memory" is a real directory), besides ":memory:" itself. The
// driver (modernc.org/sqlite) drops a plain name's query before the open, so
// "/data/secrets.db?mode=memory" is the real file /data/secrets.db.
//
// The one resolver for every file the server derives from that path: the
// server lock sidecar here, and internal/storage's pre-created database file,
// its -wal/-shm permission tightening and its migration lock. Two resolvers
// once disagreed on "file:" URIs: the lock sidecar met the plain spelling
// while the storage factory pre-created a junk relative "file:..." path and
// left the real database to be born at the process umask.
func DatabaseFile(dbPath string) (path string, isRealFile bool) {
	base, query, _ := strings.Cut(dbPath, "?")
	if rest, ok := strings.CutPrefix(base, "file:"); ok {
		rest, _, _ = strings.Cut(rest, "#")
		if hier, ok := strings.CutPrefix(rest, "//"); ok {
			if authority, p, _ := strings.Cut(hier, "/"); authority == "" || authority == "localhost" {
				rest = "/" + p
			}
		}
		if dec, err := url.PathUnescape(rest); err == nil {
			rest = dec
		}
		if rest == "" || rest == ":memory:" || strings.Contains(query, "mode=memory") {
			return "", false
		}
		return rest, true
	}
	// A plain name: the driver cuts the query only after the first byte
	// (conn.go newConn, "pos >= 1"), so a leading "?" is part of the name.
	if base == "" {
		base = dbPath
	}
	if base == "" || base == ":memory:" {
		return "", false
	}
	return base, true
}

// URISpellings are spellings SQLite opens as the database file at
// canonical (an absolute path whose directory is the working directory and
// contains a space). The tests of every DatabaseFile caller share this
// table (internal/serverguard's TestSQLiteURISpellings_MeetOnTheSameLock, internal/storage's
// file-permission and migration-lock tests), so a spelling added for one is
// checked for all.
func URISpellings(canonical string) []string {
	return []string{
		"file:" + canonical,
		"file://" + canonical,
		"file://localhost" + canonical,
		"file:" + canonical + "?_busy_timeout=5000",
		"file:" + canonical + "#frag",
		"file:" + filepath.Base(canonical),
		"file:" + strings.ReplaceAll(canonical, " ", "%20"),
		// A plain name's query is dropped before the open, "mode=memory"
		// included: this is the real file, not an in-memory database.
		canonical + "?_busy_timeout=5000&mode=memory",
	}
}

// InMemorySpellings are database paths that name no file.
var InMemorySpellings = []string{":memory:", "file::memory:", "file:x?mode=memory", "file:x.db?_busy_timeout=5000&mode=memory"}
