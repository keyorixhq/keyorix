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

// TestCheckFreeSpace_RefusesNearMaxInt64Requirement is the regression for the
// int64 overflow found while fuzzing CheckFreeSpace (reported to
// keyorix-private's coordinator inbox 2026-10-02): `needed := requiredBytes +
// requiredBytes*0.10` overflows and wraps NEGATIVE once requiredBytes is
// within ~10% of math.MaxInt64, which made `available < needed` always false
// (available is never negative) -- i.e. the function silently reported
// "enough space" for a requirement no real filesystem could ever satisfy.
// math.MaxInt64/2 (the existing test above) does NOT reach this: that
// magnitude's own +10% margin still fits in int64. Deliberately uses
// math.MaxInt64 itself, not /2, so this test is red on the pre-fix code and
// green only once the saturating-arithmetic fix actually lands.
func TestCheckFreeSpace_RefusesNearMaxInt64Requirement(t *testing.T) {
	dir := t.TempDir()
	err := CheckFreeSpace(filepath.Join(dir, "not-yet-created.tar.gz"), math.MaxInt64)
	require.Error(t, err, "CheckFreeSpace must refuse an ~8.3 EiB requirement, not silently report success "+
		"via integer overflow")
	require.Contains(t, err.Error(), "not enough free space")
}

// TestCheckFreeSpace_RefusesNegativeRequirement: a negative requiredBytes
// should never be silently treated as "nothing needed" -- fail closed with a
// clear error naming the actual problem, rather than falling through to
// CheckFreeSpace's normal arithmetic (which would otherwise make a negative
// requirement trivially "pass", for the wrong reason).
func TestCheckFreeSpace_RefusesNegativeRequirement(t *testing.T) {
	dir := t.TempDir()
	err := CheckFreeSpace(filepath.Join(dir, "not-yet-created.tar.gz"), -1)
	require.Error(t, err)
	require.Contains(t, err.Error(), "must not be negative")
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
