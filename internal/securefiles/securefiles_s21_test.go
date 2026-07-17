package securefiles

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSecureWriteFileSync_HappyPath_S21 verifies the success path: data is written
// to the file and the contents match exactly what was passed in.
func TestSecureWriteFileSync_HappyPath_S21(t *testing.T) {
	base := t.TempDir()
	data := []byte("secret-key-material")

	err := SecureWriteFileSync(base, "key.bin", data, 0600)
	require.NoError(t, err)

	got, err := os.ReadFile(filepath.Join(base, "key.bin"))
	require.NoError(t, err)
	assert.Equal(t, data, got)
}

// TestSecureWriteFileSync_FilePermissions_S21 verifies that the file is created
// (or updated) with the exact mode passed in, even when the file already existed
// with a looser mode (0644 → 0600).
func TestSecureWriteFileSync_FilePermissions_S21(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("chmod is a no-op as root")
	}
	base := t.TempDir()
	target := filepath.Join(base, "key.bin")

	// Pre-create with a looser mode.
	require.NoError(t, os.WriteFile(target, []byte("old"), 0644))

	err := SecureWriteFileSync(base, "key.bin", []byte("new"), 0600)
	require.NoError(t, err)

	info, err := os.Stat(target)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm(), "mode must be tightened to 0600")

	got, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, []byte("new"), got)
}

// TestSecureWriteFileSync_NonexistentDirectory_S21 verifies that writing to a path
// whose parent directory does not exist returns an error (open fails).
func TestSecureWriteFileSync_NonexistentDirectory_S21(t *testing.T) {
	base := t.TempDir()

	// "subdir" does not exist inside base.
	err := SecureWriteFileSync(base, "subdir/key.bin", []byte("data"), 0600)
	require.Error(t, err)
}

// TestSecureWriteFileSync_OverwritesExistingFile_S21 verifies that a second call
// with different data truncates and replaces the previous content.
func TestSecureWriteFileSync_OverwritesExistingFile_S21(t *testing.T) {
	base := t.TempDir()

	require.NoError(t, SecureWriteFileSync(base, "key.bin", []byte("first"), 0600))
	require.NoError(t, SecureWriteFileSync(base, "key.bin", []byte("second"), 0600))

	got, err := os.ReadFile(filepath.Join(base, "key.bin"))
	require.NoError(t, err)
	assert.Equal(t, []byte("second"), got, "file must contain only the second write")
}

// TestSecureWriteFileSync_EmptyData_S21 verifies that writing an empty byte slice
// succeeds and produces an empty file (not an error).
func TestSecureWriteFileSync_EmptyData_S21(t *testing.T) {
	base := t.TempDir()

	err := SecureWriteFileSync(base, "empty.bin", []byte{}, 0600)
	require.NoError(t, err)

	info, err := os.Stat(filepath.Join(base, "empty.bin"))
	require.NoError(t, err)
	assert.Equal(t, int64(0), info.Size())
}

// TestSecureWriteFileSync_NestedPath_S21 verifies that writing to a file in a
// subdirectory that already exists works correctly.
func TestSecureWriteFileSync_NestedPath_S21(t *testing.T) {
	base := t.TempDir()
	subdir := filepath.Join(base, "keys")
	require.NoError(t, os.Mkdir(subdir, 0700))

	data := []byte("nested-key")
	err := SecureWriteFileSync(base, "keys/nested.bin", data, 0600)
	require.NoError(t, err)

	got, err := os.ReadFile(filepath.Join(subdir, "nested.bin"))
	require.NoError(t, err)
	assert.Equal(t, data, got)
}

// TestSecureWriteFileSync_RejectsPathOutsideBase_S21 exercises the resolveInside
// access-denied branch via a path that escapes baseDir with "..".
func TestSecureWriteFileSync_RejectsPathOutsideBase_S21(t *testing.T) {
	base := t.TempDir()

	err := SecureWriteFileSync(base, "../../etc/passwd", []byte("x"), 0600)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "access denied")
}
