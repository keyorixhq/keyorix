package securefiles

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSecureDeleteFile_S23_RemoveError exercises the os.Remove error branch in
// SecureDeleteFile by making the parent directory read-only (no write permission)
// after creating the file. The shred passes succeed, but os.Remove then fails because
// the directory entry cannot be modified.
func TestSecureDeleteFile_S23_RemoveError(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("cannot test permission errors as root")
	}
	parent := t.TempDir()
	path := filepath.Join(parent, "dek-backup.key")
	require.NoError(t, os.WriteFile(path, []byte("secret-material"), 0600))

	// Allow reads and execs but forbid writes — the open(O_WRONLY) above still
	// succeeds because the FILE itself is 0600 (and we own it), but os.Remove
	// needs write permission on the DIRECTORY to unlink the entry.
	require.NoError(t, os.Chmod(parent, 0500))
	t.Cleanup(func() { _ = os.Chmod(parent, 0700) })

	err := SecureDeleteFile(path)
	require.Error(t, err, "SecureDeleteFile must fail when os.Remove cannot unlink the entry")
}

// TestSecureDeleteFile_S23_SyncDirErrorAfterRemove exercises the SyncDir call at the
// end of SecureDeleteFile. It writes and deletes a file in a normally-accessible
// directory (the same t.TempDir that SecureDeleteFile will try to SyncDir). This
// verifies the happy path where SyncDir succeeds — the error return is already
// covered by TestSyncDir_NonExistentPath / TestSyncDir_DevNullSyncFails elsewhere.
func TestSecureDeleteFile_S23_SyncDirSucceedsAfterDelete(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key-material.bin")
	require.NoError(t, os.WriteFile(path, []byte("material"), 0600))

	// A normal delete followed by SyncDir (the standard success path).
	require.NoError(t, SecureDeleteFile(path))
	_, err := os.Stat(path)
	assert.True(t, os.IsNotExist(err), "file must be removed")
}

// TestFixFilePerms_S23_UIDMismatchNoAutofix_WarnPath exercises the UID-mismatch +
// autofix=false branch (the "[WARN]" print-only path in FixFilePerms, line ~299).
// /dev/null is owned by root (uid 0) on macOS/Linux, so passing its exact mode
// prevents the mode-mismatch branch from firing; only the UID branch fires.
func TestFixFilePerms_S23_UIDMismatchNoAutofix_WarnPath(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("test is only meaningful for non-root users")
	}
	info, err := os.Lstat("/dev/null")
	if err != nil {
		t.Skip("cannot lstat /dev/null")
	}
	// Pass the exact actual mode so the mode-check is a no-op; only the UID
	// mismatch (root vs current user) triggers the warning branch.
	spec := FilePermSpec{Path: "/dev/null", Mode: info.Mode().Perm()}

	// autofix=false → UID mismatch → hasWarnings=true → (hasWarnings && !autofix) → error.
	// The [WARN] print at line ~299 is exercised on this call.
	err = FixFilePerms([]FilePermSpec{spec}, false)
	require.Error(t, err, "UID mismatch with autofix=false must surface as an error")
}

// TestFixFilePerms_S23_ModeCorrectUIDMismatchAutofix exercises the UID-mismatch +
// autofix=true branch where chown fails (non-root cannot chown to another owner).
// This covers the "[ERROR] Failed to chown" path inside FixFilePerms.
func TestFixFilePerms_S23_ModeCorrectUIDMismatchAutofix(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("test is only meaningful for non-root users")
	}
	info, err := os.Lstat("/dev/null")
	if err != nil {
		t.Skip("cannot lstat /dev/null")
	}
	// Pass exact mode to skip mode-mismatch; UID mismatch triggers chown attempt.
	spec := FilePermSpec{Path: "/dev/null", Mode: info.Mode().Perm()}

	// autofix=true → UID mismatch → tries Chown → fails (non-root) → unresolved=true → error.
	err = FixFilePerms([]FilePermSpec{spec}, true)
	require.Error(t, err, "failed chown must be reported as unresolved")
}

// TestIsPathInsideBase_S23_ExactBaseDir exercises the `absTarget == absBase` equality
// branch in isPathInsideBase — a path that is exactly equal to the base is "inside" it.
func TestIsPathInsideBase_S23_ExactBaseDir(t *testing.T) {
	base := t.TempDir()
	ok, err := isPathInsideBase(base, base)
	require.NoError(t, err)
	assert.True(t, ok, "the base itself must be considered inside the base")
}

// TestIsPathInsideBase_S23_ChildPath exercises the strings.HasPrefix branch:
// a path that begins with base+PathSeparator must be inside the base.
func TestIsPathInsideBase_S23_ChildPath(t *testing.T) {
	base := t.TempDir()
	child := filepath.Join(base, "sub", "file.key")
	require.NoError(t, os.MkdirAll(filepath.Dir(child), 0700))
	require.NoError(t, os.WriteFile(child, []byte("x"), 0600))

	ok, err := isPathInsideBase(base, child)
	require.NoError(t, err)
	assert.True(t, ok)
}

// TestResolveExistingAncestor_S23_DeepNonexistentPath exercises multi-level recursion
// in resolveExistingAncestor: when neither the leaf nor its parent exists, the function
// recurses until it finds a real directory, then re-attaches the missing tail segments.
func TestResolveExistingAncestor_S23_DeepNonexistentPath(t *testing.T) {
	base := t.TempDir()
	// Two missing levels deep.
	deep := filepath.Join(base, "missing1", "missing2", "key.bin")

	result := resolveExistingAncestor(deep)

	// base exists and will be resolved; the missing segments are re-appended.
	resolvedBase, err := filepath.EvalSymlinks(base)
	require.NoError(t, err)
	expected := filepath.Join(resolvedBase, "missing1", "missing2", "key.bin")
	assert.Equal(t, expected, result)
}

// TestSafeReadFile_S23_PathInsideNestedDir verifies that SafeReadFile reads a file
// nested two directories deep inside the base without error.
func TestSafeReadFile_S23_PathInsideNestedDir(t *testing.T) {
	base := t.TempDir()
	sub := filepath.Join(base, "a", "b")
	require.NoError(t, os.MkdirAll(sub, 0700))
	want := []byte("nested-content")
	require.NoError(t, os.WriteFile(filepath.Join(sub, "secret.key"), want, 0600))

	got, err := SafeReadFile(base, "a/b/secret.key")
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

// TestSafeReadFile_S23_PathValidationError exercises the "path validation error"
// return in SafeReadFile by passing a symlink-loop base directory.
func TestSafeReadFile_S23_PathValidationError(t *testing.T) {
	dir := t.TempDir()
	loop := filepath.Join(dir, "loopsafe")
	require.NoError(t, os.Symlink(loop, loop))

	_, err := SafeReadFile(loop, "key.bin")
	require.Error(t, err)
	// The error wraps the symlink-loop error from isPathInsideBase.
	assert.Contains(t, err.Error(), "path validation error")
}

// TestFixFilePerms_S23_EmptySpecList verifies that FixFilePerms returns nil for an
// empty spec list regardless of the autofix flag.
func TestFixFilePerms_S23_EmptySpecList(t *testing.T) {
	require.NoError(t, FixFilePerms([]FilePermSpec{}, false))
	require.NoError(t, FixFilePerms([]FilePermSpec{}, true))
	require.NoError(t, FixFilePerms(nil, false))
}

// TestFixFilePerms_S23_CorrectModeAndOwner verifies the no-warning happy path in
// FixFilePerms: a file with the exact mode and owned by the current user returns nil.
func TestFixFilePerms_S23_CorrectModeAndOwner(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "good.key")
	require.NoError(t, os.WriteFile(p, []byte("x"), 0600))
	require.NoError(t, os.Chmod(p, 0600))

	require.NoError(t, FixFilePerms([]FilePermSpec{{Path: p, Mode: 0600}}, false))
	require.NoError(t, FixFilePerms([]FilePermSpec{{Path: p, Mode: 0600}}, true))
}

// TestSecureWriteFileSync_S23_NestedMissingDir exercises the open-error path in
// SecureWriteFileSync when the parent subdirectory does not exist inside base.
func TestSecureWriteFileSync_S23_NestedMissingDir(t *testing.T) {
	base := t.TempDir()
	// "deepdir" does not exist.
	err := SecureWriteFileSync(base, "deepdir/key.bin", []byte("data"), 0600)
	require.Error(t, err)
}

// TestSecureWriteFile_S23_NestedMissingDir exercises the open-error path in
// SecureWriteFile when the parent subdirectory does not exist inside base.
func TestSecureWriteFile_S23_NestedMissingDir(t *testing.T) {
	base := t.TempDir()
	err := SecureWriteFile(base, "nosuchdir/key.bin", []byte("data"), 0600)
	require.Error(t, err)
}

// TestFixFilePerms_S23_AutofixModeMismatchFixed_ThenUIDCorrect verifies that
// FixFilePerms successfully fixes a mode mismatch with autofix=true when the file
// is owned by the current user (the combined fix success path).
func TestFixFilePerms_S23_AutofixModeMismatchFixed_ThenUIDCorrect(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("chmod assertions are meaningless as root")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "fix-mode.key")
	require.NoError(t, os.WriteFile(p, []byte("x"), 0644))
	require.NoError(t, os.Chmod(p, 0644))

	// autofix=true → chmod should succeed → mode tightened → no unresolved issues.
	err := FixFilePerms([]FilePermSpec{{Path: p, Mode: 0600}}, true)
	require.NoError(t, err)

	info, statErr := os.Stat(p)
	require.NoError(t, statErr)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}
