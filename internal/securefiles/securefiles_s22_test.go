package securefiles

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestResolveExistingAncestor_S22_ExistingFile verifies that a path to an existing
// file is returned with its real (symlink-resolved) form.
func TestResolveExistingAncestor_S22_ExistingFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "real.txt")
	require.NoError(t, os.WriteFile(f, []byte("x"), 0600))

	result := resolveExistingAncestor(f)
	// The result must be equal to EvalSymlinks of the file (resolves any temp-dir symlink).
	want, err := filepath.EvalSymlinks(f)
	require.NoError(t, err)
	assert.Equal(t, want, result)
}

// TestResolveExistingAncestor_S22_NonExistentFilePresentParent verifies that for a
// path whose leaf does not exist, the longest existing prefix is resolved and the
// non-existent filename tail is re-appended unchanged.
func TestResolveExistingAncestor_S22_NonExistentFilePresentParent(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "does-not-exist.key")

	result := resolveExistingAncestor(missing)
	// The parent (dir) exists; its resolved form plus the filename tail must be returned.
	resolvedDir, err := filepath.EvalSymlinks(dir)
	require.NoError(t, err)
	expected := filepath.Join(resolvedDir, "does-not-exist.key")
	assert.Equal(t, expected, result)
}

// TestSafeReadFile_S22_HappyPath verifies that SafeReadFile returns the correct
// contents for a file that exists inside the base directory.
func TestSafeReadFile_S22_HappyPath(t *testing.T) {
	base := t.TempDir()
	want := []byte("file-content-123")
	require.NoError(t, os.WriteFile(filepath.Join(base, "data.txt"), want, 0600))

	got, err := SafeReadFile(base, "data.txt")
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

// TestSafeReadFile_S22_PathEqualBase verifies that reading with an empty relative path
// (which resolves to the base itself) is denied — a directory is not a readable file.
func TestSafeReadFile_S22_EmptyRelPath(t *testing.T) {
	base := t.TempDir()
	// filepath.Join(base, "") == base; reading a directory fails with an error.
	_, err := SafeReadFile(base, "")
	require.Error(t, err)
}

// TestSecureWriteFile_S22_HappyPath verifies SecureWriteFile writes data and sets
// the correct mode on a new file.
func TestSecureWriteFile_S22_HappyPath(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("chmod assertions are meaningless as root")
	}
	base := t.TempDir()
	data := []byte("write-test-payload")

	require.NoError(t, SecureWriteFile(base, "out.key", data, 0600))

	got, err := os.ReadFile(filepath.Join(base, "out.key"))
	require.NoError(t, err)
	assert.Equal(t, data, got)

	info, err := os.Stat(filepath.Join(base, "out.key"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

// TestSecureWriteFile_S22_EmptyData verifies that writing a zero-length slice
// creates an empty file without error.
func TestSecureWriteFile_S22_EmptyData(t *testing.T) {
	base := t.TempDir()
	require.NoError(t, SecureWriteFile(base, "empty.key", []byte{}, 0600))

	info, err := os.Stat(filepath.Join(base, "empty.key"))
	require.NoError(t, err)
	assert.Equal(t, int64(0), info.Size())
}

// TestSecureWriteFile_S22_OverwriteTightensMode verifies that writing over a pre-existing
// file with a looser mode tightens it to the requested mode (the Chmod branch).
func TestSecureWriteFile_S22_OverwriteTightensMode(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("chmod assertions are meaningless as root")
	}
	base := t.TempDir()
	target := filepath.Join(base, "key.bin")
	require.NoError(t, os.WriteFile(target, []byte("old"), 0644))

	require.NoError(t, SecureWriteFile(base, "key.bin", []byte("new"), 0600))

	info, err := os.Stat(target)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())

	got, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, []byte("new"), got)
}

// TestSecureWriteFile_S22_RejectsTraversal verifies the access-denied path in
// SecureWriteFile for a ".." escape attempt.
func TestSecureWriteFile_S22_RejectsTraversal(t *testing.T) {
	base := t.TempDir()
	err := SecureWriteFile(base, "../../sensitive", []byte("x"), 0600)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "access denied")
}

// TestSecureWriteFile_S22_OpenErrorReadOnly exercises the open-file error branch
// when the existing file is read-only.
func TestSecureWriteFile_S22_OpenErrorReadOnly(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("permission test is not meaningful as root")
	}
	base := t.TempDir()
	target := filepath.Join(base, "ro.key")
	require.NoError(t, os.WriteFile(target, []byte("x"), 0600))
	require.NoError(t, os.Chmod(target, 0400))
	t.Cleanup(func() { _ = os.Chmod(target, 0600) })

	err := SecureWriteFile(base, "ro.key", []byte("new"), 0600)
	require.Error(t, err)
}

// TestSecureDeleteFile_S22_ZeroByteFile verifies that SecureDeleteFile handles a
// zero-length file without error (size=0 edge case in the overwrite loop).
func TestSecureDeleteFile_S22_ZeroByteFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.key")
	require.NoError(t, os.WriteFile(path, []byte{}, 0600))

	require.NoError(t, SecureDeleteFile(path))

	_, err := os.Stat(path)
	assert.True(t, os.IsNotExist(err), "zero-byte file must be removed")
}

// TestSecureDeleteFile_S22_LargeFile verifies that SecureDeleteFile completes
// successfully for a file larger than 4 KiB.
func TestSecureDeleteFile_S22_LargeFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "large.key")
	content := make([]byte, 8192)
	for i := range content {
		content[i] = byte(i % 256)
	}
	require.NoError(t, os.WriteFile(path, content, 0600))

	require.NoError(t, SecureDeleteFile(path))

	_, err := os.Stat(path)
	assert.True(t, os.IsNotExist(err))
}

// TestSyncDir_S22_HappyPath verifies that SyncDir succeeds for a real, existing directory.
func TestSyncDir_S22_HappyPath(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, SyncDir(dir))
}

// TestSyncDir_S22_MissingDirectory verifies that SyncDir returns an error for a
// path that does not exist.
func TestSyncDir_S22_MissingDirectory(t *testing.T) {
	err := SyncDir(filepath.Join(t.TempDir(), "no-such-dir"))
	require.Error(t, err)
}

// TestIsPathInsideBase_S22_ExactBase verifies that a path equal to the base itself
// is considered inside (it's not outside it).
func TestIsPathInsideBase_S22_ExactBase(t *testing.T) {
	base := t.TempDir()
	ok, err := isPathInsideBase(base, base)
	require.NoError(t, err)
	assert.True(t, ok)
}

// TestIsPathInsideBase_S22_SiblingSharesPrefix verifies the classic off-by-one case:
// /base/foo must NOT be reported as inside /base/f.
func TestIsPathInsideBase_S22_SiblingSharesPrefix(t *testing.T) {
	parent := t.TempDir()
	base := filepath.Join(parent, "foo")
	sibling := filepath.Join(parent, "foobar")
	require.NoError(t, os.MkdirAll(base, 0700))
	require.NoError(t, os.MkdirAll(sibling, 0700))

	ok, err := isPathInsideBase(base, sibling)
	require.NoError(t, err)
	assert.False(t, ok, "sibling sharing a prefix must not be inside the base")
}

// TestResolveInside_S22_ValidPath verifies the happy path: a clean path inside
// the base is returned without error and is an absolute path rooted within the base.
func TestResolveInside_S22_ValidPath(t *testing.T) {
	base := t.TempDir()
	got, err := resolveInside(base, "key.file")
	require.NoError(t, err)
	// resolveInside returns filepath.Clean(Join(baseDir, path)) — not EvalSymlinks —
	// so compare using the same Clean join to stay platform-independent.
	assert.Equal(t, filepath.Clean(filepath.Join(base, "key.file")), got)
	assert.True(t, filepath.IsAbs(got))
}

// TestResolveInside_S22_TraversalRejected verifies that a ".." path is rejected.
func TestResolveInside_S22_TraversalRejected(t *testing.T) {
	base := t.TempDir()
	_, err := resolveInside(base, "../escape")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "access denied")
}

// TestFixFilePerms_S22_AlreadyCorrectMode verifies that a file whose mode already
// matches the spec does not trigger an error under audit-only (autofix=false) mode.
func TestFixFilePerms_S22_AlreadyCorrectMode(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "tight.key")
	require.NoError(t, os.WriteFile(p, []byte("x"), 0600))
	require.NoError(t, os.Chmod(p, 0600))

	require.NoError(t, FixFilePerms([]FilePermSpec{{Path: p, Mode: 0600}}, false))
}

// TestFixFilePerms_S22_AutofixNoOp verifies that FixFilePerms with autofix=true
// on a correctly-permissioned file owned by the current user returns no error.
func TestFixFilePerms_S22_AutofixNoOp(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "correct.key")
	require.NoError(t, os.WriteFile(p, []byte("x"), 0600))
	require.NoError(t, os.Chmod(p, 0600))

	require.NoError(t, FixFilePerms([]FilePermSpec{{Path: p, Mode: 0600}}, true))
}

// TestFixFilePerms_S22_MixedCorrectAndBad verifies that FixFilePerms processes all
// specs even when one has the wrong mode: the bad one is reported and the good one
// is not counted as a problem.
func TestFixFilePerms_S22_MixedCorrectAndBad(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.key")
	bad := filepath.Join(dir, "bad.key")
	require.NoError(t, os.WriteFile(good, []byte("x"), 0600))
	require.NoError(t, os.Chmod(good, 0600))
	require.NoError(t, os.WriteFile(bad, []byte("y"), 0644))
	require.NoError(t, os.Chmod(bad, 0644))

	// autofix=true: fixes the bad file; good file stays untouched.
	err := FixFilePerms([]FilePermSpec{
		{Path: good, Mode: 0600},
		{Path: bad, Mode: 0600},
	}, true)
	require.NoError(t, err)

	info, serr := os.Stat(bad)
	require.NoError(t, serr)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

// TestFixFilePerms_S22_AutofixFalseMultipleIssues verifies that autofix=false with
// multiple wrong-mode files returns an error (not just the first warning).
func TestFixFilePerms_S22_AutofixFalseMultipleIssues(t *testing.T) {
	dir := t.TempDir()
	p1 := filepath.Join(dir, "a.key")
	p2 := filepath.Join(dir, "b.key")
	require.NoError(t, os.WriteFile(p1, []byte("x"), 0644))
	require.NoError(t, os.WriteFile(p2, []byte("y"), 0644))

	err := FixFilePerms([]FilePermSpec{
		{Path: p1, Mode: 0600},
		{Path: p2, Mode: 0600},
	}, false)
	require.Error(t, err)
}
