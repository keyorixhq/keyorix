// exclusive_lock_paths_test.go — PILOT-KEYPATHS-NOV-1 item 1 (#4249): the lock
// refusal names the lock file, and a relative key path produces a startup
// warning with the resolved absolute paths. Where the keys are read from is
// unchanged (relative paths still resolve against the working directory).
package encryption

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExclusiveKeyLock_RefusalNamesTheLockFile_Relative(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	require.NoError(t, os.Mkdir("keys", 0o700))

	held, err := acquireExclusiveKeyLock(".", "keys/dek.key")
	require.NoError(t, err)
	defer releaseKeyLock(held)

	_, err = acquireExclusiveKeyLock(".", "keys/dek.key")
	require.Error(t, err)
	require.Contains(t, err.Error(), "another process already holds the DEK lock")
	want, werr := filepath.EvalSymlinks(filepath.Join(dir, "keys", "dek.lock"))
	require.NoError(t, werr)
	got := err.Error()
	require.True(t, strings.Contains(got, filepath.Join(dir, "keys", "dek.lock")) || strings.Contains(got, want),
		"refusal must name the absolute lock path: %q", got)
}

// An absolute key path is unchanged: normalizeKeyPaths still reduces it to the
// key directory, and the lock sits beside the keys.
func TestExclusiveKeyLock_AbsoluteKeyPath_Unchanged(t *testing.T) {
	dir := t.TempDir()
	km := NewKeyManager("", filepath.Join(dir, "keyorix.dek"), filepath.Join(dir, "keyorix.salt"))
	require.NoError(t, km.configErr)
	require.Equal(t, dir, km.baseDir)
	require.Equal(t, "keyorix.dek", km.dekPath)

	f, err := acquireExclusiveKeyLock(km.baseDir, km.dekPath)
	require.NoError(t, err)
	defer releaseKeyLock(f)
	require.FileExists(t, filepath.Join(dir, "dek.lock"))
	require.Equal(t, filepath.Join(dir, "dek.lock"), keyLockDisplayPath(km.baseDir, km.dekPath))

	_, err = acquireExclusiveKeyLock(km.baseDir, km.dekPath)
	require.ErrorContains(t, err, filepath.Join(dir, "dek.lock"))
}

func TestRelativeKeyPathWarning(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	cwd, err := os.Getwd()
	require.NoError(t, err)

	w := RelativeKeyPathWarning("keys/dek.key", "keys/kek.salt")
	require.Contains(t, w, filepath.Join(cwd, "keys", "dek.key"))
	require.Contains(t, w, filepath.Join(cwd, "keys", "kek.salt"))
	require.Contains(t, w, filepath.Join(cwd, "keys", "dek.lock"))

	abs := filepath.Join(dir, "k")
	require.Empty(t, RelativeKeyPathWarning(filepath.Join(abs, "a.dek"), filepath.Join(abs, "a.salt")),
		"absolute key paths need no warning")
	require.Empty(t, RelativeKeyPathWarning("", ""))
}
