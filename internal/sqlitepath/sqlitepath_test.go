package sqlitepath

import "testing"

// REVFIX-3732-2 (REVIEW-3732-DEEP-1 M1): modernc.org/sqlite strips the query
// off a name that does not start with "file:" before sqlite3_open_v2, so
// "mode=memory" there is ignored and SQLite opens a real file. Taking it for
// in-memory skipped the 0600 pre-create, the server lock sidecar and the
// migration lock for a real database.
func TestDatabaseFile(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		real     bool
	}{
		{"/data/secrets.db", "/data/secrets.db", true},
		{"/data/mode=memory/secrets.db", "/data/mode=memory/secrets.db", true},
		{"plain.db?_busy_timeout=5000&mode=memory", "plain.db", true},
		{"/data/secrets.db?mode=memory", "/data/secrets.db", true},
		// The driver strips a query only after the first byte: a leading
		// "?" is part of the file name.
		{"?mode=memory", "?mode=memory", true},
		{"file:/data/secrets.db?_busy_timeout=5000", "/data/secrets.db", true},
		{"file:///data/my%20data/secrets.db#frag", "/data/my data/secrets.db", true},
		{"file://localhost/data/secrets.db", "/data/secrets.db", true},
		{"", "", false},
		{":memory:", "", false},
		{":memory:?_busy_timeout=5000", "", false},
		{"file::memory:", "", false},
		{"file::memory:?_busy_timeout=5000", "", false},
		{"file:x?mode=memory", "", false},
		{"file:x.db?_busy_timeout=5000&mode=memory", "", false},
	} {
		got, real := DatabaseFile(tc.in)
		if got != tc.want || real != tc.real {
			t.Errorf("DatabaseFile(%q) = %q, %v; want %q, %v", tc.in, got, real, tc.want, tc.real)
		}
	}
}

// The shared tables agree with DatabaseFile, so a spelling moved between them
// is checked here as well as by every caller's tests.
func TestSharedSpellingTables(t *testing.T) {
	for _, s := range URISpellings("/data/my data/secrets.db") {
		if _, real := DatabaseFile(s); !real {
			t.Errorf("URISpellings entry %q resolves to no file", s)
		}
	}
	for _, s := range InMemorySpellings {
		if _, real := DatabaseFile(s); real {
			t.Errorf("InMemorySpellings entry %q resolves to a file", s)
		}
	}
}
