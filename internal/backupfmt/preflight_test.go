package backupfmt

import (
	"math"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCheckFreeSpace_PassesForATinyRequirement(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, CheckFreeSpace(filepath.Join(dir, "not-yet-created.tar.gz"), 1))
}

func TestCheckFreeSpace_RefusesAnImpossibleRequirement(t *testing.T) {
	dir := t.TempDir()
	err := CheckFreeSpace(filepath.Join(dir, "not-yet-created.tar.gz"), math.MaxInt64/2)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not enough free space")
}

func TestCheckFreeSpace_WalksUpToNearestExistingAncestor(t *testing.T) {
	dir := t.TempDir()
	// Neither "does-not-exist-yet" nor "also-missing.db" exists -- only dir
	// itself does. Must not error just because the leaf path is missing.
	require.NoError(t, CheckFreeSpace(filepath.Join(dir, "does-not-exist-yet", "also-missing.db"), 1))
}

func TestAvailableBytes_ReturnsAPositiveNumberForATempDir(t *testing.T) {
	n, err := AvailableBytes(t.TempDir())
	require.NoError(t, err)
	require.Positive(t, n)
}
