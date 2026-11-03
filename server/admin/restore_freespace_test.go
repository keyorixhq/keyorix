package admin

import (
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
)

// TestSaturatingQuadruple_NormalSizesUnaffected: the common case -- a real
// archive file's size -- must multiply exactly as before, no behavior change
// for any realistic input.
func TestSaturatingQuadruple_NormalSizesUnaffected(t *testing.T) {
	require.Equal(t, int64(0), saturatingQuadruple(0))
	require.Equal(t, int64(400), saturatingQuadruple(100))
	require.Equal(t, int64(4*1024*1024*1024), saturatingQuadruple(1024*1024*1024)) // a real 1GiB archive
}

// TestSaturatingQuadruple_ClampsNearMaxInt64 is the regression for the
// overflow found alongside internal/backupfmt.CheckFreeSpace's own: n*4 for
// n close to math.MaxInt64 overflows int64 and can wrap NEGATIVE, which would
// otherwise reach CheckFreeSpace as a requiredBytes that LOOKS like "needs
// almost nothing" instead of "needs an impossible amount" -- the opposite of
// a fail-closed preflight check. Asserts the clamp fires before that
// multiplication ever happens.
func TestSaturatingQuadruple_ClampsNearMaxInt64(t *testing.T) {
	require.Equal(t, int64(math.MaxInt64), saturatingQuadruple(math.MaxInt64))
	require.Equal(t, int64(math.MaxInt64), saturatingQuadruple(math.MaxInt64/4+1))
	require.NotEqual(t, int64(math.MaxInt64/4), saturatingQuadruple(math.MaxInt64/4),
		"sanity: the exact boundary must still multiply normally, not clamp early")
}

// TestSaturatingQuadruple_NegativeInputClamped: os.FileInfo.Size() cannot
// actually be negative for a real file, but this must still fail closed
// (clamp to the maximum, which CheckFreeSpace then refuses) rather than
// silently pass a negative requiredBytes through to CheckFreeSpace's own
// now-dedicated negative-input refusal for a confusing, indirect reason.
func TestSaturatingQuadruple_NegativeInputClamped(t *testing.T) {
	require.Equal(t, int64(math.MaxInt64), saturatingQuadruple(-1))
}

// TestRestore_FreeSpaceCheckedWhereItStages: the pre-flight free-space check
// runs on the staging directory (under $TMPDIR, often a different and smaller
// filesystem than the archive's), not on the archive's directory. A sparse
// archive whose 4x estimate (32 TiB) no runner has free must be refused with
// an error naming the staging directory under TMPDIR, before anything is
// extracted, and the staging directory must be removed again. Red before
// SCALE-OPS-1: the check ran on the archive's directory and named no
// staging path. 8 TiB keeps the sparse file under ext4's 16 TiB file limit.
//
// Not t.Parallel(): package-level restoreInput, TMPDIR and chdir.
func TestRestore_FreeSpaceCheckedWhereItStages(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "huge.tar.gz")
	f, err := os.Create(archive)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	require.NoError(t, os.Truncate(archive, 1<<43))

	stagingRoot := t.TempDir()
	t.Setenv("TMPDIR", stagingRoot)
	t.Chdir(t.TempDir()) // the default ./secrets.db target must not exist

	old := restoreInput
	restoreInput = archive
	t.Cleanup(func() { restoreInput = old })

	err = runAdminRestoreV2(&config.Config{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "free-space check for the staging directory")
	require.Contains(t, err.Error(), filepath.Join(stagingRoot, "keyorix-admin-restore-"))
	require.Contains(t, err.Error(), "set TMPDIR")
	// The wrapper above names stagingDir whatever path was measured; only
	// CheckFreeSpace's own error quotes the path it actually checked.
	require.Contains(t, err.Error(), "not enough free space at \""+filepath.Join(stagingRoot, "keyorix-admin-restore-"))

	left, err := os.ReadDir(stagingRoot)
	require.NoError(t, err)
	require.Empty(t, left, "the refused restore must remove its staging directory")
}
