package keyfiles

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// FuzzSafePathConfinement is a sink-guided harness for the filesystem-path sink
// family. Every config-driven key-material path (salt, DEK, per-provider
// wrapped-key / shamir-share paths, recursively through Fallbacks) passes
// through SafePath before securefiles.FixFilePerms Lstat/Chmod/Chowns it, so
// SafePath is the confinement gate for those sinks.
//
//	INVARIANT: if SafePath accepts a path (returns a nil error), the cleaned
//	result contains no ".." path segment; consequently a RELATIVE accepted
//	path, joined under any base directory, stays inside that base — a
//	config-driven traversal cannot steer FixFilePerms at a file above the base.
//
// The ".."-segment check and the base-confinement check are written
// independently of SafePath's own `strings.Contains(clean, "..")` test, so
// weakening SafePath makes them diverge (see the sinkmap REPORT red-proof run).
//
// What this oracle does NOT verify:
//   - SafePath deliberately PERMITS absolute paths (resolve() handles those
//     separately), so the confinement assertion is made only for relative
//     accepted paths; an absolute accepted path is checked solely for the
//     no-".."-segment property.
//   - It does not follow symlinks or touch the filesystem — it reasons about
//     the lexical path only. Symlink-time escape is securefiles' concern, not
//     SafePath's, and is out of scope here.
//   - It asserts only the accept⇒safe direction; it does not assert that every
//     safe path is accepted (SafePath is intentionally conservative and also
//     rejects innocuous names containing the substring "..").
func FuzzSafePathConfinement(f *testing.F) {
	f.Add("key/dek.bin")
	f.Add("../../etc/passwd")
	f.Add("a/../../../b")
	f.Add("/abs/salt.bin")
	f.Add("./nested/wrapped.key")
	f.Add("..")

	const base = "/var/lib/keyorix/keys"

	f.Fuzz(func(t *testing.T, path string) {
		clean, err := SafePath("fuzz", path)
		if err != nil {
			return // rejected — nothing to confine
		}
		if hasDotDotSegment(clean) {
			t.Fatalf("SafePath accepted %q -> %q which still has a '..' segment", path, clean)
		}
		if filepath.IsAbs(clean) {
			return // absolute paths are permitted by design; confinement N/A
		}
		joined := filepath.Clean(filepath.Join(base, clean))
		if joined != base && !strings.HasPrefix(joined, base+string(os.PathSeparator)) {
			t.Fatalf("relative path %q accepted by SafePath escaped base %q: %q", path, base, joined)
		}
	})
}

// hasDotDotSegment reports whether any path SEGMENT of p is exactly "..",
// scanning both separators so the check is OS-independent and distinct from
// SafePath's substring test.
func hasDotDotSegment(p string) bool {
	segs := strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == filepath.Separator })
	return slices.Contains(segs, "..")
}
