package resguard

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

// TestResguardImportedOnlyFromTests enforces INV-RES-test-only: no NON-test .go
// file anywhere in the repo may import this package. It is test-only
// infrastructure (it imports testing and installs process-wide seams); a
// non-test import would link it — and its testing dependency — into a shipped
// binary. The check walks the tree for the import path in a file that is not a
// _test.go. srcpath.RepoRoot resolves the checkout even under -trimpath; if it
// cannot (binary run away from the checkout) the test skips rather than passing
// blind.
func TestResguardImportedOnlyFromTests(t *testing.T) {
	root := repoRootOrSkip(t)
	const importPath = `"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"`

	var offenders []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "vendor" || d.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		b, e := os.ReadFile(p) // #nosec G304 -- walking this repo's own tree
		if e != nil {
			return nil
		}
		if strings.Contains(string(b), importPath) {
			rel, _ := filepath.Rel(root, p)
			offenders = append(offenders, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(offenders) > 0 {
		t.Fatalf("resguard is test-only but is imported by non-test file(s): %s", strings.Join(offenders, ", "))
	}
}

func repoRootOrSkip(t *testing.T) string {
	t.Helper()
	var root string
	func() {
		defer func() {
			if recover() != nil {
				root = ""
			}
		}()
		root = srcpath.RepoRoot()
	}()
	if root == "" {
		t.Skip("repo root not resolvable (binary run away from checkout)")
	}
	return root
}
