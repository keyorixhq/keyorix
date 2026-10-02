package backupfmt

import (
	"math"
	"path/filepath"
	"testing"
)

// FuzzCheckFreeSpaceMonotonic fuzzes two non-negative requiredBytes values
// against the SAME path and asserts CheckFreeSpace is monotonic in
// requiredBytes: if the smaller of the two is already refused (not enough
// space), the larger one must be refused too -- asking for MORE space can
// never turn a refusal into an acceptance. This doesn't require knowing the
// "correct" absolute threshold (the real available-bytes number depends on
// the machine running the test), which is what makes it a sound oracle
// across arbitrary magnitudes, INCLUDING the boundary where a naive
// `requiredBytes + requiredBytes*margin` computation overflows int64 and
// wraps negative -- exactly the bug this target was added to catch (filed
// to keyorix-private's coordinator inbox 2026-10-02, fixed in the same PR
// that added this fuzz target; see preflight.go's CheckFreeSpace doc
// comment). Negative inputs are deliberately out of scope here (skipped,
// not clamped): CheckFreeSpace's negative-requiredBytes refusal is an
// unconditional short-circuit unrelated to the "more space needed" ordering
// this oracle checks, and the two don't compose across that boundary (a
// refused -1 says nothing about whether 0, which is always accepted, should
// also be refused).
func FuzzCheckFreeSpaceMonotonic(f *testing.F) {
	f.Add(int64(0), int64(1))
	f.Add(int64(1), int64(math.MaxInt64))
	f.Add(int64(math.MaxInt64/2), int64(math.MaxInt64))
	f.Add(int64(math.MaxInt64-1), int64(math.MaxInt64))
	f.Add(int64(math.MaxInt64), int64(math.MaxInt64))

	f.Fuzz(func(t *testing.T, a, b int64) {
		if a < 0 || b < 0 {
			t.Skip()
		}
		small, large := a, b
		if small > large {
			small, large = large, small
		}

		dir := t.TempDir()
		path := filepath.Join(dir, "not-yet-created.tar.gz")

		smallErr := CheckFreeSpace(path, small)
		largeErr := CheckFreeSpace(path, large)

		if smallErr != nil && largeErr == nil {
			t.Fatalf("CheckFreeSpace(%d) was refused but CheckFreeSpace(%d) (a LARGER requirement) was accepted -- "+
				"not monotonic: smallErr=%v largeErr=%v", small, large, smallErr, largeErr)
		}
	})
}
