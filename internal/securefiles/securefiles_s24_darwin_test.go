//go:build darwin

package securefiles

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rlimitFsize temporarily sets RLIMIT_FSIZE to the given value, returning a restore
// function. The caller must defer the restore immediately.
func rlimitFsize(t *testing.T, cur uint64) func() {
	t.Helper()
	var old syscall.Rlimit
	require.NoError(t, syscall.Getrlimit(syscall.RLIMIT_FSIZE, &old))
	require.NoError(t, syscall.Setrlimit(syscall.RLIMIT_FSIZE, &syscall.Rlimit{Cur: cur, Max: old.Max}))
	return func() {
		_ = syscall.Setrlimit(syscall.RLIMIT_FSIZE, &old)
	}
}

// TestSecureWriteFile_S24_WriteError_RLIMIT exercises the f.Write error path
// in SecureWriteFile (lines 125-128). With RLIMIT_FSIZE=0 any non-empty write to
// a newly-truncated file fails with EFBIG, so the open and Chmod both succeed but
// the Write returns an error.
func TestSecureWriteFile_S24_WriteError_RLIMIT(t *testing.T) {
	base := t.TempDir()
	// Pre-create so O_TRUNC (not O_CREAT) is exercised.
	require.NoError(t, os.WriteFile(filepath.Join(base, "key.bin"), []byte("old-content"), 0600))

	restore := rlimitFsize(t, 0)
	defer restore()

	// Non-empty data: Write will fail with EFBIG since the file is truncated to 0
	// by O_TRUNC and RLIMIT_FSIZE=0 prevents growing it.
	err := SecureWriteFile(base, "key.bin", []byte("new-secret"), 0600)
	require.Error(t, err, "Write must fail when RLIMIT_FSIZE=0 prevents file growth")
}

// TestSecureWriteFileSync_S24_WriteError_RLIMIT exercises the f.Write error path
// in SecureWriteFileSync (lines 153-156). Same mechanism as above.
func TestSecureWriteFileSync_S24_WriteError_RLIMIT(t *testing.T) {
	base := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(base, "dek.bin"), []byte("old-key-material"), 0600))

	restore := rlimitFsize(t, 0)
	defer restore()

	err := SecureWriteFileSync(base, "dek.bin", []byte("new-key-material"), 0600)
	require.Error(t, err, "Write must fail when RLIMIT_FSIZE=0 prevents file growth")
}

// TestSecureDeleteFile_S24_WriteAtError_RLIMIT exercises the f.WriteAt error path
// inside the overwrite closure (line 208-210 inside the closure) and the resulting
// "shred pass (random) failed" error return (lines 213-216).
// With RLIMIT_FSIZE=0, any write that results in file size > 0 fails. The file has
// size > 0 before SecureDeleteFile opens it (O_WRONLY, no truncation), so the first
// WriteAt(buf, 0) attempt (with buf size == original file size > 0) fails.
func TestSecureDeleteFile_S24_WriteAtError_RLIMIT(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dek-backup.key")
	// Non-empty file so WriteAt will try to write > 0 bytes.
	require.NoError(t, os.WriteFile(path, []byte("secret-key-bytes"), 0600))

	restore := rlimitFsize(t, 0)
	defer restore()

	err := SecureDeleteFile(path)
	require.Error(t, err, "SecureDeleteFile must fail when RLIMIT_FSIZE=0 prevents the overwrite pass")
	assert.Contains(t, err.Error(), "shred pass")
}
