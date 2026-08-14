package secret

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCreateExportFile_ModeAndSymlinkSafety pins #114: an exported-secrets file
// was created with os.Create (0644, world-readable) and would silently write
// through a pre-planted symlink. createSecureOutputFile must produce a 0600 file and
// refuse a symlinked or already-existing target.
func TestCreateExportFile_ModeAndSymlinkSafety(t *testing.T) {
	dir := t.TempDir()

	t.Run("creates a 0600 file", func(t *testing.T) {
		target := filepath.Join(dir, "out.env")
		f, err := createSecureOutputFile(target)
		require.NoError(t, err)
		defer f.Close() //nolint:errcheck

		info, err := f.Stat()
		require.NoError(t, err)
		if runtime.GOOS != "windows" {
			assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "export file must not be group/world-readable")
		}
	})

	t.Run("refuses an already-existing path", func(t *testing.T) {
		target := filepath.Join(dir, "exists.env")
		require.NoError(t, os.WriteFile(target, []byte("old"), 0o600))
		_, err := createSecureOutputFile(target)
		require.Error(t, err, "O_EXCL must refuse to overwrite/write-through a pre-existing path")
	})

	t.Run("refuses a pre-planted symlink target", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink semantics differ on windows")
		}
		evilTarget := filepath.Join(dir, "attacker-owned.txt")
		link := filepath.Join(dir, "planted-link.env")
		require.NoError(t, os.Symlink(evilTarget, link))
		_, err := createSecureOutputFile(link)
		require.Error(t, err, "a symlinked target must be refused, not followed")
		_, statErr := os.Stat(evilTarget)
		assert.True(t, os.IsNotExist(statErr), "the symlink target must never have been created/written")
	})
}
