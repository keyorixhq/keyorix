package auditverify

// REVIEW-4553-DEEP-1 L1: a -wal that is not a regular file is refused instead
// of silently dropped from the private copy.

import (
	"os"
	"strings"
	"testing"
)

// A -wal beside a WAL-mode artifact that is a directory is an open error, not
// a copy of the main file alone, and leaves no copy behind.
func TestOpenSQLiteReadOnly_NonRegularWALRefused(t *testing.T) {
	tmp := privateTMPDIR(t)
	path := writeWALAuditDB(t, t.TempDir(), 3)
	if err := os.Mkdir(path+"-wal", 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := OpenSQLiteReadOnly(path)
	if err == nil {
		_ = db.Close()
		t.Fatal("want an error for a -wal that is a directory, got a DB")
	}
	if !strings.Contains(err.Error(), "audit.db-wal is not a regular file") {
		t.Fatalf("want an error naming the non-regular -wal, got %v", err)
	}
	assertEmptyDir(t, tmp, "private copy after a refused -wal")
}
