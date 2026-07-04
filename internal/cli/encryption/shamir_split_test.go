package encryption

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// #269: a dangling symlink planted at a share output path (its target not yet
// existing, so a pre-write os.Stat existence check wouldn't catch it) must not
// be silently written through — the write should fail rather than create the
// Shamir key-share material at the symlink's target location outside --out-dir.
func TestShamirSplit_RefusesToFollowSymlinkAtTarget(t *testing.T) {
	dir := t.TempDir()
	outsideTarget := filepath.Join(t.TempDir(), "exfiltrated-share-1.hex")
	require.NoError(t, os.Symlink(outsideTarget, filepath.Join(dir, "share-1.hex")))

	ssShares, ssThreshold, ssOutDir = 5, 3, dir
	err := shamirSplitCmd.RunE(shamirSplitCmd, nil)
	require.Error(t, err, "writing through a pre-planted symlink must be refused")

	_, statErr := os.Stat(outsideTarget)
	assert.True(t, os.IsNotExist(statErr), "the symlink target must NOT have been created")
}

func TestShamirSplit_WritesSharesWithSecurePermissions(t *testing.T) {
	dir := t.TempDir()
	ssShares, ssThreshold, ssOutDir = 5, 3, dir
	require.NoError(t, shamirSplitCmd.RunE(shamirSplitCmd, nil))

	for i := 1; i <= 5; i++ {
		path := filepath.Join(dir, fmt.Sprintf("share-%d.hex", i))
		fi, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm(), "%s must be 0600", path)
	}
}
