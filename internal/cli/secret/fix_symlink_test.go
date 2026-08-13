package secret

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestApplyFix_RefusesSymlinkTarget is #G26: applyFix used os.WriteFile, which follows
// a symlink at the resolved path and writes through it. A scanned directory can contain
// attacker-planted content, so a symlink swapped in at a discovered finding's path
// (between the scan and the apply) would let `secret fix` overwrite an arbitrary file
// the process can write to. O_NOFOLLOW must refuse it instead.
func TestApplyFix_RefusesSymlinkTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on windows")
	}
	basePath := t.TempDir()
	evilTarget := filepath.Join(basePath, "attacker-owned.txt")
	require.NoError(t, os.WriteFile(evilTarget, []byte("do-not-touch"), 0o600))
	link := filepath.Join(basePath, "config.py")
	require.NoError(t, os.Symlink(evilTarget, link))

	plan := fixPlan{
		File:         "config.py",
		Line:         1,
		OriginalLine: `API_KEY = "sk-realvalue"`,
		NewLine:      `API_KEY = os.getenv("API_KEY")`,
	}
	err := applyFix(basePath, plan)
	require.Error(t, err, "a symlinked finding path must be refused, not followed")

	content, rerr := os.ReadFile(evilTarget)
	require.NoError(t, rerr)
	assert.Equal(t, "do-not-touch", string(content), "the symlink target must never be overwritten")
}

// TestApplyFix_WritesRegularFile confirms the O_NOFOLLOW fix didn't break the ordinary
// (non-symlink) apply path.
func TestApplyFix_WritesRegularFile(t *testing.T) {
	basePath := t.TempDir()
	target := filepath.Join(basePath, "config.py")
	require.NoError(t, os.WriteFile(target, []byte(`API_KEY = "sk-realvalue"`), 0o600))

	plan := fixPlan{
		File:         "config.py",
		Line:         1,
		OriginalLine: `API_KEY = "sk-realvalue"`,
		NewLine:      `API_KEY = os.getenv("API_KEY")`,
	}
	require.NoError(t, applyFix(basePath, plan))

	content, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, `API_KEY = os.getenv("API_KEY")`, string(content))
}
