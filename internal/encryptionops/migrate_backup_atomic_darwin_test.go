//go:build darwin

package encryptionops

import (
	"bytes"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// limitFileSize lowers the soft RLIMIT_FSIZE to cur and restores the previous
// limit in t.Cleanup, so a Fatal or panic between the two cannot leave every
// later file write in the package failing (AUDIT-HIGHWATER-CAS-1 leftover).
func limitFileSize(t *testing.T, cur uint64) {
	t.Helper()
	var old syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &old); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &old); err != nil {
			t.Errorf("restoring RLIMIT_FSIZE: %v", err)
		}
	})
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &syscall.Rlimit{Cur: cur, Max: old.Max}); err != nil {
		t.Fatal(err)
	}
}

// The file-size limit a test lowers must be back when that test ends, including
// when it ends early.
func TestLimitFileSize_RestoresTheLimitWhenTheTestEnds(t *testing.T) {
	var before, after syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &before); err != nil {
		t.Fatal(err)
	}
	t.Run("lowers", func(t *testing.T) {
		limitFileSize(t, 16)
		var during syscall.Rlimit
		if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &during); err != nil {
			t.Fatal(err)
		}
		if during.Cur != 16 {
			t.Fatalf("limit not lowered: %d", during.Cur)
		}
	})
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &after); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("RLIMIT_FSIZE leaked: before %+v, after %+v", before, after)
	}
}

// A restore whose write fails part-way (RLIMIT_FSIZE below the backup's size, as
// a full disk would) must leave the active DEK as it was. When RestoreBackup
// rewrote the active file in place (O_TRUNC, then write), the failed write left
// it truncated: neither the old nor the new wrapped DEK (REVIEW-ENCRYPTIONOPS-1 R1).
func TestRestoreBackup_FailedWriteLeavesTheActiveDEKIntact(t *testing.T) {
	dir := chdirTemp(t)
	backup := bytes.Repeat([]byte("B"), 64)
	active := bytes.Repeat([]byte("A"), 64)
	for name, data := range map[string][]byte{"backup.bin": backup, "active.bin": active} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	limitFileSize(t, 16)
	RestoreBackup(dir, "backup.bin", "active.bin", nil)

	got, err := os.ReadFile(filepath.Join(dir, "active.bin")) // #nosec G304 -- t.TempDir() path
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, active) {
		t.Fatalf("a failed restore write tore the active DEK: got %d bytes %q, want the previous %d bytes", len(got), got, len(active))
	}
}
