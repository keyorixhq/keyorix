package admin

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"
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
