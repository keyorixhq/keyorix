package encryptionops

// REVIEW-ENCRYPTIONOPS-1 R1: migrate-provider's rollback must never leave a torn
// active DEK, and its backup must never overwrite an earlier backup.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func readTestFile(t *testing.T, path string) []byte {
	t.Helper()
	got, err := os.ReadFile(path) // #nosec G304 -- t.TempDir() path
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return got
}

// A crash after the backup's bytes are staged and before the rename leaves the
// active DEK exactly as it was (here: the re-wrapped one), never a partial file;
// the next run (or an operator) still has both the active file and the backup.
func TestRestoreBackup_CrashBeforeRenameLeavesTheActiveDEKIntact(t *testing.T) {
	dir := chdirTemp(t)
	backup := []byte("backup-wrapped-dek-under-the-old-kek-0123456789")
	active := []byte("re-wrapped-dek-under-the-target-kek-abcdefghij")
	writeTestFile(t, filepath.Join(dir, "backup.bin"), backup)
	writeTestFile(t, filepath.Join(dir, "active.bin"), active)

	var points []string
	migrateRestoreCrashHook = func(point string) bool {
		points = append(points, point)
		return point == "before-rename"
	}
	t.Cleanup(func() { migrateRestoreCrashHook = nil })

	RestoreBackup(dir, "backup.bin", "active.bin", nil)

	if len(points) == 0 {
		t.Fatal("RestoreBackup never reached the before-rename step")
	}
	if got := readTestFile(t, filepath.Join(dir, "active.bin")); !bytes.Equal(got, active) {
		t.Fatalf("a crash before the rename changed the active DEK: got %q, want %q", got, active)
	}
	if got := readTestFile(t, filepath.Join(dir, "backup.bin")); !bytes.Equal(got, backup) {
		t.Fatalf("a crash before the rename changed the backup: got %q", got)
	}
	// The staged copy is complete and carries the migrate-backup name, so
	// `migrate-provider cleanup` finds it.
	if got := readTestFile(t, filepath.Join(dir, "backup.bin.restoring")); !bytes.Equal(got, backup) {
		t.Fatalf("staged restore file = %q, want the backup's bytes", got)
	}

	// Without the crash the same call completes: the active DEK is the backup.
	migrateRestoreCrashHook = nil
	RestoreBackup(dir, "backup.bin", "active.bin", nil)
	if got := readTestFile(t, filepath.Join(dir, "active.bin")); !bytes.Equal(got, backup) {
		t.Fatalf("restore after the crash: active = %q, want the backup", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "backup.bin.restoring")); !os.IsNotExist(err) {
		t.Fatalf("the staging file must be renamed away by a completed restore, stat err = %v", err)
	}
	if mode := fileMode(t, filepath.Join(dir, "active.bin")); mode != 0o600 {
		t.Fatalf("restored DEK mode = %v, want 0600", mode)
	}
}

// Two backups taken in the same instant (the old name had one-second
// resolution) get different names, and neither overwrites the other.
func TestCreateMigrateBackup_SameInstantGetsDistinctNamesAndNeverOverwrites(t *testing.T) {
	dir := chdirTemp(t)
	fixed := time.Unix(1_700_000_000, 0)
	migrateBackupNow = func() time.Time { return fixed }
	t.Cleanup(func() { migrateBackupNow = time.Now })

	first := []byte("wrapped-dek-generation-1")
	second := []byte("wrapped-dek-generation-2")
	writeTestFile(t, filepath.Join(dir, "dek.key"), first)
	b1, err := CreateMigrateBackup(dir, "dek.key")
	if err != nil {
		t.Fatalf("first backup: %v", err)
	}
	writeTestFile(t, filepath.Join(dir, "dek.key"), second)
	b2, err := CreateMigrateBackup(dir, "dek.key")
	if err != nil {
		t.Fatalf("second backup: %v", err)
	}
	if b1 == b2 {
		t.Fatalf("two backups in the same instant got the same name %q", b1)
	}
	for _, b := range []string{b1, b2} {
		if !strings.HasPrefix(b, "dek.key.migrate-backup.") {
			t.Fatalf("backup %q lost the migrate-backup prefix that cleanup and rotate-kek look for", b)
		}
	}
	if got := readTestFile(t, filepath.Join(dir, b1)); !bytes.Equal(got, first) {
		t.Fatalf("the first backup was overwritten: %q", got)
	}
	if got := readTestFile(t, filepath.Join(dir, b2)); !bytes.Equal(got, second) {
		t.Fatalf("the second backup = %q, want %q", got, second)
	}
	if mode := fileMode(t, filepath.Join(dir, b1)); mode != 0o600 {
		t.Fatalf("backup mode = %v, want 0600", mode)
	}
	found, err := FindMigrateBackups(dir, "dek.key")
	if err != nil || len(found) != 2 {
		t.Fatalf("FindMigrateBackups = %v, %v; want both backups", found, err)
	}
}

// Even a full name collision (same instant, same random suffix) never truncates
// an existing backup: O_EXCL refuses it, the next attempt takes a fresh name, and
// when every attempt collides the backup fails instead of overwriting.
func TestCreateMigrateBackup_NameCollisionNeverTruncates(t *testing.T) {
	dir := chdirTemp(t)
	fixed := time.Unix(1_700_000_000, 0)
	origSuffix := migrateBackupSuffix
	t.Cleanup(func() { migrateBackupNow = time.Now; migrateBackupSuffix = origSuffix })
	migrateBackupNow = func() time.Time { return fixed }
	suffixes := []string{"deadbeef", "deadbeef", "cafef00d"}
	migrateBackupSuffix = func() (string, error) {
		s := suffixes[0]
		if len(suffixes) > 1 {
			suffixes = suffixes[1:]
		}
		return s, nil
	}

	writeTestFile(t, filepath.Join(dir, "dek.key"), []byte("current"))
	taken := "dek.key.migrate-backup.1700000000000000000-deadbeef"
	writeTestFile(t, filepath.Join(dir, taken), []byte("earlier-backup"))

	got, err := CreateMigrateBackup(dir, "dek.key")
	if err != nil {
		t.Fatalf("CreateMigrateBackup: %v", err)
	}
	if got != "dek.key.migrate-backup.1700000000000000000-cafef00d" {
		t.Fatalf("backup name = %q, want the first unused one", got)
	}
	if b := readTestFile(t, filepath.Join(dir, taken)); string(b) != "earlier-backup" {
		t.Fatalf("an existing backup was overwritten: %q", b)
	}

	// Every attempt collides: refuse, and leave the existing backup alone.
	migrateBackupSuffix = func() (string, error) { return "deadbeef", nil }
	if _, err := CreateMigrateBackup(dir, "dek.key"); err == nil {
		t.Fatal("CreateMigrateBackup succeeded although every name was taken")
	}
	if b := readTestFile(t, filepath.Join(dir, taken)); string(b) != "earlier-backup" {
		t.Fatalf("an existing backup was overwritten: %q", b)
	}
}

func TestCreateMigrateBackup_RefusesPathTraversal(t *testing.T) {
	dir := chdirTemp(t)
	writeTestFile(t, filepath.Join(dir, "dek.key"), []byte("secret"))
	if _, err := CreateMigrateBackup(dir, "../dek.key"); err == nil {
		t.Fatal("expected CreateMigrateBackup to refuse a DEK path that escapes baseDir")
	}
}
