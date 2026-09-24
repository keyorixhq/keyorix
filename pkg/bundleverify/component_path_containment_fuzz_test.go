package bundleverify

// FuzzComponentPathContainment fuzzes cleanComponentPath — the per-entry path-traversal gate the
// bundle EXTRACT/staging loop applies to every tar header name (bundle.go: `cleanComponentPath(hdr.Name)`)
// before writing a verified component under the operator's --dest directory. The existing
// FuzzBundleVerify only exercises the read-only Verify path, which stages nothing; this covers the
// containment check that decides where bytes land on disk, the real path-traversal surface.
//
// Sound invariant (assert only the accept direction — a reject is always safe, so it cannot
// false-positive): whatever name cleanComponentPath ACCEPTS must, when joined under a destination
// directory the way the extractor joins it, stay inside that directory — never absolute, never an
// escape via "..". An accepted name that resolves outside destDir is a path traversal by definition.
//
// Pure function, no disk I/O — CI-runnable.

import (
	"path/filepath"
	"strings"
	"testing"
)

func FuzzComponentPathContainment(f *testing.F) {
	for _, s := range []string{
		"manifest.json", "a", "a/b/c", "sub/dir/file.bin", // benign accepts
		"", " ", ".", "..", "./a", "a/..", "a/b/../../..", // dot shapes
		"../escape", "../../etc/passwd", "/abs", "//x", "///y", // absolute / traversal
		"a/../b", "a/../../b", "a/./b", "trailing/", "  ../spaced",
		`a\..\..\b`, "a\x00b", "nested/../../../../root", // backslash (Windows), NUL, deep climb
	} {
		f.Add(s)
	}

	// A fixed absolute destination the extractor would stage under.
	destDir := filepath.Join(string(filepath.Separator)+"tmp", "kx-bundle-dest")

	f.Fuzz(func(t *testing.T, p string) {
		name, err := cleanComponentPath(p)
		if err != nil {
			return // rejected — always safe; we never assert "must accept"
		}

		// An accepted name must be relative (never absolute / leading-slash).
		if filepath.IsAbs(name) || strings.HasPrefix(name, "/") {
			t.Fatalf("PATH TRAVERSAL: cleanComponentPath accepted %q -> %q which is absolute", p, name)
		}

		// Joined under destDir the way the extractor joins it, it must stay inside destDir.
		full := filepath.Join(destDir, filepath.FromSlash(name))
		rel, rerr := filepath.Rel(destDir, full)
		if rerr != nil {
			t.Fatalf("PATH TRAVERSAL: cleanComponentPath accepted %q -> %q; Rel(destDir, full) failed: %v", p, name, rerr)
		}
		if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			t.Fatalf("PATH TRAVERSAL: cleanComponentPath accepted %q -> %q which escapes destDir (rel=%q full=%q)", p, name, rel, full)
		}
	})
}
