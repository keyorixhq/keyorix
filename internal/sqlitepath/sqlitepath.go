// Package sqlitepath resolves a SQLite storage.database.path value to the file
// SQLite opens. It has no dependencies so that both internal/serverguard (the
// server lock sidecar) and internal/storage (the database file's permissions
// and the migration lock) use the one resolver.
package sqlitepath

import (
	"path/filepath"
	"strconv"
	"strings"
)

// DatabaseFile resolves a storage.database.path value to the file
// SQLite opens, and reports whether there is one at all. A SQLite URI filename
// ("file:/data/secrets.db", "file:///...", "file://localhost/...",
// percent-encoded, with a query or fragment) resolves to the same path as its
// plain spelling; a query (DSN parameters) is never part of the path. The
// path is decoded as sqlite3ParseUri decodes it: each valid %HH on its own, a
// "%" without two hex digits kept literal, and a decoded %00 ending the path
// ("file:/d/100%/my%20db" is "/d/100%/my db", "file:/d/a.db%00x" is
// "/d/a.db"). Only
// a "file:" URI's query marks a database in-memory, when its last "mode" key
// is exactly "memory" (a directory named "mode=memory" is a real directory,
// "_journal_mode=memory" is a real file), besides ":memory:" itself. The
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
	base, _, _ := strings.Cut(dbPath, "?")
	if rest, ok := strings.CutPrefix(dbPath, "file:"); ok {
		// SQLite ends a URI at "#" before it looks for "?".
		rest, _, _ = strings.Cut(rest, "#")
		rest, query, _ := strings.Cut(rest, "?")
		if hier, ok := strings.CutPrefix(rest, "//"); ok {
			if authority, p, _ := strings.Cut(hier, "/"); authority == "" || authority == "localhost" {
				rest = "/" + p
			}
		}
		// Decoded per octet like the query, not with url.PathUnescape, which
		// rejects the whole path on one malformed "%" and keeps a NUL.
		rest = sqliteURIUnescape(rest)
		if rest == "" || rest == ":memory:" || uriModeIsMemory(query) {
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

// uriModeIsMemory reports whether a file: URI's query (already cut at "#")
// opens the database in memory. SQLite reads only the "mode" key and the
// last one wins (each one replaces the open mode), so "_journal_mode=memory",
// "xmode=memory" or "mode=memory&mode=rwc" name a real file. The query is
// read the way sqlite3ParseUri reads it, not with url.ParseQuery: only a
// literal "&" or "=" delimits, "+" is not a space, and a decoded %00 drops
// the rest of its key or value ("mode=memory&mode%00x=rwc" is mode=rwc).
func uriModeIsMemory(query string) bool {
	last := ""
	for pair := range strings.SplitSeq(query, "&") {
		key, val, _ := strings.Cut(pair, "=")
		if sqliteURIUnescape(key) == "mode" {
			last = sqliteURIUnescape(val)
		}
	}
	return last == "memory"
}

// sqliteURIUnescape decodes %HH as sqlite3ParseUri does: a "%" not followed
// by two hex digits is literal, and a decoded NUL ends the string.
func sqliteURIUnescape(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if octet, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
				if octet == 0 {
					break
				}
				out = append(out, byte(octet))
				i += 2
				continue
			}
		}
		out = append(out, s[i])
	}
	return string(out)
}

// URISpellings are spellings SQLite opens as the database file at
// canonical (an absolute path whose directory is the working directory and
// contains a space and a literal "%" not followed by two hex digits, so the
// %20 spelling mixes a valid escape with a malformed one). The tests of every DatabaseFile caller share this
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
		// A decoded %00 ends the path.
		"file:" + canonical + "%00junk",
		// A plain name's query is dropped before the open, "mode=memory"
		// included: this is the real file, not an in-memory database.
		canonical + "?_busy_timeout=5000&mode=memory",
		// A file: URI's query is in-memory only when its last "mode" key
		// is exactly "memory", and "#" ends the query.
		"file:" + canonical + "?_journal_mode=memory",
		"file:" + canonical + "?_pragma=journal_mode=memory",
		"file:" + canonical + "?xmode=memory",
		"file:" + canonical + "?mode=memory&mode=rwc",
		"file:" + canonical + "#f?mode=memory",
	}
}

// InMemorySpellings are database paths that name no file.
var InMemorySpellings = []string{":memory:", "file::memory:", "file:x?mode=memory", "file:x.db?_busy_timeout=5000&mode=memory", "file:x.db?mode=rwc&mode=memory"}
