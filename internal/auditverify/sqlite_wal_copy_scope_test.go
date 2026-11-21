package auditverify

// REVIEW-4553-DEEP-1 M1: the private copy is the whole vault database, so only
// an operator-named artifact gets one; a server-owned file opens in place.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A server-owned WAL-mode file opened in place needs no temporary directory:
// it verifies with TMPDIR pointing at a directory that does not exist.
func TestOpenSQLiteReadOnlyInPlace_WALFileNeedsNoTempDir(t *testing.T) {
	dir := t.TempDir()
	path := writeWALAuditDB(t, dir, 3)
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "missing"))

	if _, err := OpenSQLiteReadOnly(path); err == nil || !strings.Contains(err.Error(), "temporary directory") {
		t.Fatalf("test premise: the copying open should need TMPDIR, got %v", err)
	}
	db, err := OpenSQLiteReadOnlyInPlace(path)
	if err != nil {
		t.Fatalf("OpenSQLiteReadOnlyInPlace: %v", err)
	}
	if dir := db.PrivateCopyDir(); dir != "" {
		t.Errorf("in-place open reports a private copy in %s", dir)
	}
	res, err := Verify(context.Background(), db, Options{})
	if cerr := db.Close(); cerr != nil {
		t.Errorf("Close: %v", cerr)
	}
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Verdict == VerdictBroken {
		t.Fatalf("verdict %s (%s), want not BROKEN", res.Verdict, res.Reason)
	}
}

// RemovePrivateCopy deletes the copy while the handle is still open (the
// signal path), and a later Close neither fails nor removes anything twice.
func TestRemovePrivateCopy_BeforeCloseRemovesCopy(t *testing.T) {
	tmp := privateTMPDIR(t)
	path := writeWALAuditDB(t, t.TempDir(), 3)
	db, err := OpenSQLiteReadOnly(path)
	if err != nil {
		t.Fatalf("OpenSQLiteReadOnly: %v", err)
	}
	ents, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 || !strings.HasPrefix(ents[0].Name(), "keyorix-audit-verify-") {
		t.Fatalf("test premise: want one private copy directory in TMPDIR, got %v", ents)
	}
	if got, want := db.PrivateCopyDir(), filepath.Join(tmp, ents[0].Name()); got != want {
		t.Errorf("PrivateCopyDir() = %q, want %q", got, want)
	}
	db.RemovePrivateCopy()
	assertEmptyDir(t, tmp, "private copy after RemovePrivateCopy")
	db.RemovePrivateCopy()
	if err := db.Close(); err != nil {
		t.Errorf("Close after RemovePrivateCopy: %v", err)
	}
	assertEmptyDir(t, tmp, "private copy after Close")
}
