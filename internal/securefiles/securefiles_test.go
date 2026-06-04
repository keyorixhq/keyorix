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
