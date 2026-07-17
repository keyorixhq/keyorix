package securefiles

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSecureWriteFileSync_RejectsTraversal exercises the resolveInside error branch
// in SecureWriteFileSync (the path escapes baseDir via "..").
func TestSecureWriteFileSync_RejectsTraversal(t *testing.T) {
	base := t.TempDir()
	err := SecureWriteFileSync(base, "../escape-sync.key", []byte("x"), 0600)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "access denied")

	// Nothing was written outside the base.
	_, statErr := os.Stat(filepath.Join(filepath.Dir(base), "escape-sync.key"))
	assert.True(t, os.IsNotExist(statErr), "escaped file must not be created")
}

// TestSecureWriteFileSync_RefusesDanglingSymlink exercises the O_NOFOLLOW branch
// in SecureWriteFileSync: a dangling final-component symlink inside the base must
// not be followed (the write must fail, not create the symlink's target outside).
func TestSecureWriteFileSync_RefusesDanglingSymlink(t *testing.T) {
	base := t.TempDir()
	outside := filepath.Join(filepath.Dir(base), "escape-sync-link.key")
	// A symlink "link.key" inside base pointing at a not-yet-existing file outside.
	require.NoError(t, os.Symlink(outside, filepath.Join(base, "link.key")))

	err := SecureWriteFileSync(base, "link.key", []byte("secret"), 0600)
	require.Error(t, err, "writing through a final-component symlink must be refused")

	_, statErr := os.Stat(outside)
	assert.True(t, os.IsNotExist(statErr), "symlink target outside base must not be created")
}

// TestSecureWriteFileSync_WriteErrorPath exercises the Write error path by writing
// to a file inside a directory without write permission, so the open succeeds but
// write fails — on most platforms the open will fail, so we accept either error.
// The main goal is hitting the write-failure branch (or the open-failure branch).
func TestSecureWriteFileSync_OpenErrorPath(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("permission test is not meaningful as root")
	}
	base := t.TempDir()
	// Create the file first so it exists.
	target := filepath.Join(base, "key.file")
	require.NoError(t, os.WriteFile(target, []byte("old"), 0600))
	// Make the file read-only so O_WRONLY fails.
	require.NoError(t, os.Chmod(target, 0400))
	t.Cleanup(func() { _ = os.Chmod(target, 0600) })

	err := SecureWriteFileSync(base, "key.file", []byte("new"), 0600)
	require.Error(t, err, "open of a read-only file for writing must fail")
}

// TestSecureWriteFileSync_SymlinkLoopBase exercises the resolveInside error path
// in SecureWriteFileSync when the baseDir is a symlink loop (EvalSymlinks → ELOOP).
func TestSecureWriteFileSync_SymlinkLoopBase(t *testing.T) {
	dir := t.TempDir()
	loop := filepath.Join(dir, "loopsync")
	require.NoError(t, os.Symlink(loop, loop))

	err := SecureWriteFileSync(loop, "key.file", []byte("data"), 0600)
	require.Error(t, err)
}
