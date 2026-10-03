package backupfmt

import (
	"fmt"
	"math"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// safetyMarginFraction is added on top of the raw required-bytes estimate
// before comparing against available space (design §7.4: "plus a safety
// margin") -- neither backup's own on-disk-size estimate nor restore's
// manifest-declared uncompressed size accounts for filesystem overhead
// (block rounding, journal/WAL sidecars, the archive's own gzip framing),
// so a check that only compared the raw number against the raw free space
// would let through cases that are real shortfalls in practice.
const safetyMarginFraction = 0.10

// AvailableBytes returns the free space available to a normal (non-root)
// process on the filesystem containing path -- unix.Statfs's Bavail field,
// not Bfree, since Bfree includes space reserved for the superuser, which
// this process cannot actually use (matching df's own default behavior,
// not `df -x`).
func AvailableBytes(path string) (int64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0, fmt.Errorf("statfs %q: %w", path, err)
	}
	// #nosec G115 -- Bavail/Bsize are filesystem block counts/sizes, never
	// large enough in practice to overflow int64 once multiplied; the
	// platform's own df reports the identical numbers without special-casing this.
	return int64(st.Bavail) * int64(st.Bsize), nil
}

// CheckFreeSpace refuses with a clear, specific error (design §7.4) if the
// filesystem containing path does not have at least requiredBytes plus
// safetyMarginFraction of headroom available. path itself need not exist
// yet -- the common case for both callers design §7.4 names: `admin backup
// --output` (the archive file doesn't exist yet) and `admin restore`
// staging (§5.3's temporary directory doesn't exist yet either) -- so this
// walks up to the nearest existing ancestor directory before statfs-ing it.
func CheckFreeSpace(path string, requiredBytes int64) error {
	if requiredBytes < 0 {
		return fmt.Errorf("check free space: requiredBytes must not be negative, got %d", requiredBytes)
	}

	statPath := path
	for {
		if _, err := os.Stat(statPath); err == nil {
			break
		}
		parent := filepath.Dir(statPath)
		if parent == statPath {
			return fmt.Errorf("check free space: no existing ancestor directory found for %q", path)
		}
		statPath = parent
	}

	available, err := AvailableBytes(statPath)
	if err != nil {
		return fmt.Errorf("check free space at %q: %w", statPath, err)
	}
	// needed := requiredBytes + requiredBytes*safetyMarginFraction overflows
	// int64 and WRAPS NEGATIVE once requiredBytes is within ~10% of
	// math.MaxInt64, which made this check silently report "enough space"
	// for a requirement no real filesystem could ever satisfy (found while
	// reading this file during the session that later added
	// FuzzCheckFreeSpaceMonotonic (preflight_fuzz_test.go) -- confirmed by
	// direct arithmetic first, this file had no fuzz coverage of its own yet
	// at the time. TestCheckFreeSpace_RefusesAnImpossibleRequirement's prior
	// MaxInt64/2 case never hit this since that magnitude doesn't overflow).
	// Saturate instead of adding the margin once requiredBytes alone already
	// exceeds half of MaxInt64 -- the margin can only ever push the refusal
	// further in the fail-closed direction at that point, never the other way.
	var needed int64
	if requiredBytes > math.MaxInt64/2 {
		needed = math.MaxInt64
	} else {
		needed = requiredBytes + int64(float64(requiredBytes)*safetyMarginFraction)
	}
	if available < needed {
		return fmt.Errorf("not enough free space at %q: need approximately %d bytes (%d plus a %.0f%% safety margin), "+
			"only %d bytes available", statPath, needed, requiredBytes, safetyMarginFraction*100, available)
	}
	return nil
}
