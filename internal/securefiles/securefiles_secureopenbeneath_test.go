package securefiles

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSecureOpenBeneath_RefusesIntermediateSymlink_Direct is a deterministic (non-race)
// companion to the TOCTOU race tests in securefiles_intermediate_symlink_toctou_test.go:
// it plants the intermediate-component symlink BEFORE calling SecureOpenBeneath at all
// (no timing dependency), pinning the baseline guarantee that the per-component walk
// refuses to traverse a symlinked directory component outright, independent of any race
// window. This exercises SecureOpenBeneath directly, so it only compiles against the
// fixed implementation (the pre-fix codebase has no such function) — the race tests are
// the ones that demonstrate the actual pre-fix vulnerability via the public API.
func TestSecureOpenBeneath_RefusesIntermediateSymlink_Direct(t *testing.T) {
	base := t.TempDir()
	outside := t.TempDir()
	require.NoError(t, os.Symlink(outside, filepath.Join(base, "tenant")))

	f, err := SecureOpenBeneath(base, filepath.Join("tenant", "secret.bin"), 0, 0)
	require.Error(t, err, "an intermediate path component that is a symlink must be refused")
	if f != nil {
		_ = f.Close()
	}
	_, statErr := os.Stat(filepath.Join(outside, "secret.bin"))
	assert.True(t, os.IsNotExist(statErr))
}
