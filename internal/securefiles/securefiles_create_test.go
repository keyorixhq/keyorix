package securefiles

// Regression tests for SecureCreateFile/SecureCreateFileSync/SecureCreateFileHandle —
// see keyorix-private/adversarial-review/QUEUE.md "Group 2 — Safe file writes". These
// combine SecureWriteFile's per-path-component O_NOFOLLOW walk with O_EXCL (previously
// only in internal/cli/secret/export.go's createSecureOutputFile), into one shared
// create-only helper used across internal/cli/{secret,rbac,compliance,trust}.

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecureCreateFile_CreatesFreshFileWithPerm(t *testing.T) {
	base := t.TempDir()
	want := []byte("fresh-bytes")
	require.NoError(t, SecureCreateFile(base, "out.txt", want, 0600))

	info, err := os.Stat(filepath.Join(base, "out.txt"))
	require.NoError(t, err)
	if runtime.GOOS != "windows" {
		assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
	}
	got, err := SafeReadFile(base, "out.txt")
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestSecureCreateFile_RefusesPreexistingRegularFile(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "already-there.txt")
	require.NoError(t, os.WriteFile(target, []byte("old"), 0o600))

	err := SecureCreateFile(base, "already-there.txt", []byte("new"), 0600)
	require.Error(t, err, "O_EXCL must refuse to overwrite a pre-existing file")

	got, rerr := os.ReadFile(target) //nolint:gosec // test-controlled fixed path
	require.NoError(t, rerr)
	assert.Equal(t, "old", string(got), "the pre-existing file's content must be left untouched")
}

func TestSecureCreateFile_RefusesPrePlantedSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on windows")
	}
	base := t.TempDir()
	outside := filepath.Join(filepath.Dir(base), "attacker-owned.txt")
	link := filepath.Join(base, "planted-link.txt")
	require.NoError(t, os.Symlink(outside, link))

	err := SecureCreateFile(base, "planted-link.txt", []byte("secret"), 0600)
	require.Error(t, err, "a symlinked target must be refused, not followed")
	_, statErr := os.Stat(outside)
	assert.True(t, os.IsNotExist(statErr), "the symlink target must never have been created/written")
}

func TestSecureCreateFile_RejectsTraversal(t *testing.T) {
	base := t.TempDir()
	err := SecureCreateFile(base, "../escape.txt", []byte("x"), 0600)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "access denied")
	_, statErr := os.Stat(filepath.Join(filepath.Dir(base), "escape.txt"))
	assert.True(t, os.IsNotExist(statErr))
}

func TestSecureCreateFileSync_CreatesFreshFileDurably(t *testing.T) {
	base := t.TempDir()
	want := []byte("durable-fresh-bytes")
	require.NoError(t, SecureCreateFileSync(base, "sync.txt", want, 0600))

	got, err := SafeReadFile(base, "sync.txt")
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestSecureCreateFileSync_RefusesPreexistingFile(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "existing.key")
	require.NoError(t, os.WriteFile(target, []byte("old-key"), 0o600))

	err := SecureCreateFileSync(base, "existing.key", []byte("new-key"), 0600)
	require.Error(t, err)

	got, rerr := os.ReadFile(target) //nolint:gosec // test-controlled fixed path
	require.NoError(t, rerr)
	assert.Equal(t, "old-key", string(got))
}

func TestSecureCreateFileHandle_StreamingWriteAndClose(t *testing.T) {
	base := t.TempDir()
	f, err := SecureCreateFileHandle(base, "stream.csv", 0600)
	require.NoError(t, err)
	_, werr := f.WriteString("a,b,c\n1,2,3\n")
	require.NoError(t, werr)
	require.NoError(t, f.Close())

	info, err := os.Stat(filepath.Join(base, "stream.csv"))
	require.NoError(t, err)
	if runtime.GOOS != "windows" {
		assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
	}
	got, err := SafeReadFile(base, "stream.csv")
	require.NoError(t, err)
	assert.Equal(t, "a,b,c\n1,2,3\n", string(got))
}

func TestSecureCreateFileHandle_RefusesPreexistingFile(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "matrix.json")
	require.NoError(t, os.WriteFile(target, []byte("{}"), 0o644))

	_, err := SecureCreateFileHandle(base, "matrix.json", 0600)
	require.Error(t, err, "a pre-existing destination must be refused, not silently truncated/overwritten")

	got, rerr := os.ReadFile(target) //nolint:gosec // test-controlled fixed path
	require.NoError(t, rerr)
	assert.Equal(t, "{}", string(got), "the pre-existing file must be left completely untouched")
}

func TestSecureCreateFileHandle_RefusesIntermediateSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on windows")
	}
	base := t.TempDir()
	outsideDir := t.TempDir()
	// Plant a symlink AT an intermediate directory component pointing outside base --
	// the property SecureCreateFile has that a bare final-component-O_NOFOLLOW open
	// (like the pre-fix openSecureOutputFile) does not.
	require.NoError(t, os.Symlink(outsideDir, filepath.Join(base, "subdir")))

	_, err := SecureCreateFileHandle(base, "subdir/out.txt", 0600)
	require.Error(t, err, "a symlink at an intermediate path component must be refused")

	_, statErr := os.Stat(filepath.Join(outsideDir, "out.txt"))
	assert.True(t, os.IsNotExist(statErr), "nothing must have been created through the planted intermediate symlink")
}
