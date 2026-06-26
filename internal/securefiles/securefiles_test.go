package securefiles

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsPathInsideBase(t *testing.T) {
	cases := []struct {
		base, target string
		want         bool
	}{
		{"/a/b", "/a/b", true},         // base itself
		{"/a/b", "/a/b/c", true},       // child
		{"/a/b", "/a/b/c/d", true},     // descendant
		{"/a/b", "/a", false},          // parent
		{"/a/b", "/a/bc", false},       // sibling sharing a prefix (the classic guard)
		{"/a/b", "/a/b/../c", false},   // escapes via ..
		{"/a/b", "/etc/passwd", false}, // unrelated absolute
	}
	for _, c := range cases {
		got, err := isPathInsideBase(c.base, c.target)
		require.NoError(t, err)
		assert.Equalf(t, c.want, got, "isPathInsideBase(%q, %q)", c.base, c.target)
	}
}

func TestSecureWriteAndReadRoundTrip(t *testing.T) {
	base := t.TempDir()
	want := []byte("secret-bytes")

	// SecureWriteFile does not create parent dirs (callers do); mimic that.
	require.NoError(t, os.MkdirAll(filepath.Join(base, "keys"), 0700))
	require.NoError(t, SecureWriteFile(base, "keys/dek.key", want, 0600))

	// Perm is applied as requested.
	info, err := os.Stat(filepath.Join(base, "keys/dek.key"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())

	got, err := SafeReadFile(base, "keys/dek.key")
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestSecureWriteFileSyncRoundTripAndPerms(t *testing.T) {
	base := t.TempDir()
	want := []byte("durable-key-bytes")
	require.NoError(t, SecureWriteFileSync(base, "dek.key", want, 0600))

	info, err := os.Stat(filepath.Join(base, "dek.key"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())

	got, err := SafeReadFile(base, "dek.key")
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestSecureWriteFileSyncEnforcesPermsOnExistingFile(t *testing.T) {
	base := t.TempDir()
	// A pre-existing file with looser perms must be tightened to the requested mode
	// (O_TRUNC alone keeps the old mode; the explicit Chmod fixes it).
	require.NoError(t, os.WriteFile(filepath.Join(base, "dek.key"), []byte("old"), 0644))
	require.NoError(t, SecureWriteFileSync(base, "dek.key", []byte("new"), 0600))

	info, err := os.Stat(filepath.Join(base, "dek.key"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
	got, err := SafeReadFile(base, "dek.key")
	require.NoError(t, err)
	assert.Equal(t, []byte("new"), got)
}

func TestSecureWriteFileSyncRejectsTraversal(t *testing.T) {
	base := t.TempDir()
	err := SecureWriteFileSync(base, "../escape.key", []byte("x"), 0600)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "access denied")
	_, statErr := os.Stat(filepath.Join(filepath.Dir(base), "escape.key"))
	assert.True(t, os.IsNotExist(statErr))
}

func TestSyncDir(t *testing.T) {
	base := t.TempDir()
	// A real directory syncs without error.
	require.NoError(t, SyncDir(base))
	// A missing directory surfaces the open error rather than silently passing.
	require.Error(t, SyncDir(filepath.Join(base, "does-not-exist")))
}

func TestSafeReadFileRejectsTraversal(t *testing.T) {
	base := t.TempDir()
	// Plant a file outside the base to make the test meaningful.
	outside := filepath.Join(filepath.Dir(base), "outside.txt")
	require.NoError(t, os.WriteFile(outside, []byte("nope"), 0600))
	t.Cleanup(func() { _ = os.Remove(outside) })

	_, err := SafeReadFile(base, "../outside.txt")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "access denied")
}

func TestSecureWriteFileRejectsTraversal(t *testing.T) {
	base := t.TempDir()
	err := SecureWriteFile(base, "../escape.txt", []byte("x"), 0600)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "access denied")
	// Nothing was written outside the base.
	_, statErr := os.Stat(filepath.Join(filepath.Dir(base), "escape.txt"))
	assert.True(t, os.IsNotExist(statErr))
}

func TestFixFilePermsAuditReportsWrongMode(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "loose.key")
	require.NoError(t, os.WriteFile(p, []byte("x"), 0644))
	require.NoError(t, os.Chmod(p, 0644)) // defeat umask for a deterministic mode

	// Audit only (autofix=false): wrong mode is a warning → error, file unchanged.
	err := FixFilePerms([]FilePermSpec{{Path: p, Mode: 0600}}, false)
	require.Error(t, err)
	info, _ := os.Stat(p)
	assert.Equal(t, os.FileMode(0644), info.Mode().Perm(), "audit must not modify the file")
}

// Fail closed: when autofix is on but the fix can't actually be applied (here, the file
// doesn't exist so stat fails), FixFilePerms must return an error rather than silently
// reporting success — the previous `hasWarnings && !autofix` form returned nil, hiding an
// unlocked-down key file.
func TestFixFilePermsAutofixFailsClosedOnUnresolvable(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.key")
	err := FixFilePerms([]FilePermSpec{{Path: missing, Mode: 0600}}, true)
	require.Error(t, err, "an unresolvable problem must fail even under autofix")
}

func TestFixFilePermsAutofixCorrectsMode(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "loose.key")
	require.NoError(t, os.WriteFile(p, []byte("x"), 0644))
	require.NoError(t, os.Chmod(p, 0644))

	require.NoError(t, FixFilePerms([]FilePermSpec{{Path: p, Mode: 0600}}, true))
	info, _ := os.Stat(p)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

func TestFixFilePermsCorrectModeNoWarning(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "tight.key")
	require.NoError(t, os.WriteFile(p, []byte("x"), 0600))
	require.NoError(t, os.Chmod(p, 0600))

	// Correct mode, owned by the current user → no warnings, no error.
	require.NoError(t, FixFilePerms([]FilePermSpec{{Path: p, Mode: 0600}}, false))
}

func TestFixFilePermsMissingFileWarns(t *testing.T) {
	err := FixFilePerms([]FilePermSpec{{Path: filepath.Join(t.TempDir(), "absent"), Mode: 0600}}, false)
	require.Error(t, err)
}

// TestContainmentRejectsSymlinkEscape pins the symlink-containment fix: a symlink
// planted inside baseDir that points outside it must not let a read or write escape.
func TestContainmentRejectsSymlinkEscape(t *testing.T) {
	base := t.TempDir()
	outside := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("top secret"), 0o600))

	// A symlink inside baseDir that resolves to the outside directory.
	require.NoError(t, os.Symlink(outside, filepath.Join(base, "link")))

	// Reading through the symlink must be denied (the resolved path is outside base).
	_, err := SafeReadFile(base, "link/secret.txt")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "outside")

	// Writing through the symlink (target does not exist yet) must also be denied.
	err = SecureWriteFile(base, "link/planted.txt", []byte("x"), 0o600)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "outside")

	// The outside directory must be untouched by the rejected write.
	_, statErr := os.Stat(filepath.Join(outside, "planted.txt"))
	assert.True(t, os.IsNotExist(statErr), "rejected write must not create a file outside base")
}
