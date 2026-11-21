package auditverify

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

// A rollback-journal file is still opened in place (no copy is made), and a
// database in use by a SQLite process (its -wal and -shm present in a writable
// directory) is read in place, not copied while its owner writes.
func TestOpenSQLiteReadOnly_NoCopyWhenNotNeeded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.db")
	if err := os.WriteFile(path, buildSmallAuditDB(t, 2, nil), 0o600); err != nil {
		t.Fatal(err)
	}
	if sqliteNeedsPrivateCopy(path) {
		t.Error("a rollback-journal file without a -wal was copied")
	}

	live := writeWALAuditDB(t, t.TempDir(), 2)
	if !sqliteNeedsPrivateCopy(live) {
		t.Error("a WAL-header file is not copied")
	}
	w, err := sql.Open("sqlite", live)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()
	if _, err := w.Exec(`INSERT INTO system_metadata (key, value) VALUES ('k', 'v')`); err != nil {
		t.Fatal(err)
	}
	if sqliteNeedsPrivateCopy(live) {
		t.Error("an in-use database (-wal and -shm present, writable directory) was copied")
	}
	if res := verifySQLiteFile(t, live); res.Verdict != VerdictValid {
		t.Errorf("in-use database: verdict %s: %s", res.Verdict, res.Reason)
	}
}
