//go:build darwin

package encryptionops

import (
	"bytes"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

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

	var old syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &old); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &syscall.Rlimit{Cur: 16, Max: old.Max}); err != nil {
		t.Fatal(err)
	}
	RestoreBackup(dir, "backup.bin", "active.bin", nil)
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &old); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(filepath.Join(dir, "active.bin")) // #nosec G304 -- t.TempDir() path
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, active) {
		t.Fatalf("a failed restore write tore the active DEK: got %d bytes %q, want the previous %d bytes", len(got), got, len(active))
	}
}
