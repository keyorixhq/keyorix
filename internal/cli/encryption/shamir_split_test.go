package encryption

import (
	"bytes"
	"fmt"
	"io"
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

// captureStderr redirects os.Stderr for the duration of fn and returns everything
// written to it, so tests can assert on the operator-facing warning independently
// of the (separately captured) stdout share output.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stderr = w
	fn()
	require.NoError(t, w.Close())
	os.Stderr = old
	var buf bytes.Buffer
	_, err = io.Copy(&buf, r)
	require.NoError(t, err)
	return buf.String()
}

// cli-encryption-005: printing Shamir shares to stdout (the default, no --out-dir)
// must be preceded by a loud warning on stderr — each share is genuine key material
// below the configured threshold, and stdout alone may end up in scrollback, a
// tmux/screen log, a session recorder, or a CI log. The warning goes to stderr (not
// stdout) specifically so it survives even when the operator pipes/redirects stdout
// away from the terminal.
func TestShamirSplit_WarnsOnStderrWhenPrintingSharesToStdout(t *testing.T) {
	ssShares, ssThreshold, ssOutDir = 5, 3, ""

	var stdout string
	stderr := captureStderr(t, func() {
		stdout = captureStdout(t, func() {
			require.NoError(t, shamirSplitCmd.RunE(shamirSplitCmd, nil))
		})
	})

	assert.Contains(t, stderr, "WARNING", "must warn loudly before printing shares to stdout")
	assert.Contains(t, stderr, "stdout")
	assert.Contains(t, stderr, "--out-dir", "warning must recommend the safer alternative")
	assert.Contains(t, stdout, "share 1:", "shares must still print to stdout (unchanged default behavior)")
	assert.NotContains(t, stdout, "WARNING", "the warning itself must not land on stdout")
}

// The warning is specific to the stdout path — writing shares to --out-dir doesn't
// put key material on the terminal, so no stderr warning should fire.
func TestShamirSplit_NoStderrWarningWhenWritingToOutDir(t *testing.T) {
	dir := t.TempDir()
	ssShares, ssThreshold, ssOutDir = 5, 3, dir

	stderr := captureStderr(t, func() {
		require.NoError(t, shamirSplitCmd.RunE(shamirSplitCmd, nil))
	})

	assert.Empty(t, stderr, "no stdout-specific warning should print when shares are written to --out-dir")
}
