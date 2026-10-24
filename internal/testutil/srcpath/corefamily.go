package srcpath

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

// The core family (ADR-116) is internal/core plus every package extracted from
// it. Source-scanning guards that look at "every core file" must look at the
// whole family, otherwise a file moved out of internal/core silently drops out
// of the guard (R5). The extracted-package registry is also the list R1 checks
// (internal/core/ports: no family member imports internal/core).
//
// coreFamilyExtracted is declared EMPTY on purpose. Each extraction PR adds one
// file, corefamily_<leaf>.go in this package, whose init() calls
// registerCoreFamilyDir (CLAUDE.md, "Test registry tables": one file per entry).
// It is a plain map in a non-test file because both internal/core/ports and the
// guards in internal/core and internal/core/guards read it.
//
// Registering a dir OUTSIDE internal/core also needs a look at the WalkDir
// guards rooted at internal/core: they recurse, so they see subpackages of
// internal/core, but not internal/<leaf>.
var coreFamilyExtracted = map[string]string{}

// CoreDir is internal/core, relative to the repository root.
const CoreDir = "internal/core"

// CoreTestOnlyDirs are the packages ADR-116 creates for tests only
// (decision 2): no production file may import them (R3, internal/core/guards)
// and internal/core's production closure must not contain them (R2,
// internal/core/ports). Repository-relative; they need not exist yet.
var CoreTestOnlyDirs = []string{
	"internal/core/coretests",
	"internal/core/storage/storagetest",
}

var (
	coreFamilyMu    sync.Mutex
	coreFamilyExtra []string // absolute dirs added by AddCoreFamilyDirForTesting
)

// registerCoreFamilyDir adds one extracted package directory (repository-relative,
// slash-separated) with the PR or brief that extracted it. It panics on a
// duplicate, on internal/core itself and on a path that is not clean and relative.
func registerCoreFamilyDir(rel, reason string) {
	if rel == "" || reason == "" {
		panic("srcpath: registerCoreFamilyDir needs a dir and a reason")
	}
	if rel == CoreDir || filepath.IsAbs(rel) || filepath.ToSlash(filepath.Clean(rel)) != rel || strings.HasPrefix(rel, "..") {
		panic(fmt.Sprintf("srcpath: core family dir %q must be a clean repository-relative path other than %s", rel, CoreDir))
	}
	if prev, dup := coreFamilyExtracted[rel]; dup {
		panic(fmt.Sprintf("srcpath: core family dir %q registered twice (%q and %q)", rel, prev, reason))
	}
	coreFamilyExtracted[rel] = reason
}

// CoreFamilyExtractedDirs returns the registered extracted package directories,
// repository-relative and sorted. internal/core itself is not in the list.
func CoreFamilyExtractedDirs() []string {
	dirs := make([]string, 0, len(coreFamilyExtracted))
	for rel := range coreFamilyExtracted {
		dirs = append(dirs, rel)
	}
	slices.Sort(dirs)
	return dirs
}

// CoreFamilyDirs returns the absolute directories of the core family:
// internal/core first, then every registered extracted package (sorted), then
// any directory a running test added with AddCoreFamilyDirForTesting.
func CoreFamilyDirs() []string {
	root := RepoRoot()
	dirs := []string{filepath.Join(root, filepath.FromSlash(CoreDir))}
	for _, rel := range CoreFamilyExtractedDirs() {
		dirs = append(dirs, filepath.Join(root, filepath.FromSlash(rel)))
	}
	coreFamilyMu.Lock()
	defer coreFamilyMu.Unlock()
	return append(dirs, coreFamilyExtra...)
}

// CoreFamilyGoFiles returns the absolute paths, sorted, of every non-test .go
// file directly inside each CoreFamilyDirs directory (not in subdirectories:
// a subpackage of internal/core is its own package, registered on its own when
// it is part of the family). Callers apply their own further exclusions (for
// example generated files) by name.
func CoreFamilyGoFiles() ([]string, error) {
	var files []string
	for _, dir := range CoreFamilyDirs() {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, fmt.Errorf("srcpath: core family dir: %w", err)
		}
		for _, e := range entries {
			n := e.Name()
			if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
				continue
			}
			files = append(files, filepath.Join(dir, n))
		}
	}
	slices.Sort(files)
	return files, nil
}

// CoreFamilyRel returns the key guards use for a core family file: the bare
// file name for a file in internal/core (so existing "file.go:Func" allowlist
// keys stay valid), otherwise the slash-separated path relative to the
// repository root (or the absolute path for a directory outside it).
func CoreFamilyRel(path string) string {
	root := RepoRoot()
	if filepath.Dir(path) == filepath.Join(root, filepath.FromSlash(CoreDir)) {
		return filepath.Base(path)
	}
	if rel, err := filepath.Rel(root, path); err == nil && !strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(path)
}

// AddCoreFamilyDirForTesting adds an absolute directory to CoreFamilyDirs until
// the test ends. It is for coverage tests that prove a walker follows the family
// list. Do not call it from a test that runs in parallel (t.Parallel): it changes
// what every other running guard sees.
func AddCoreFamilyDirForTesting(t testing.TB, absDir string) {
	t.Helper()
	if !filepath.IsAbs(absDir) {
		t.Fatalf("srcpath: AddCoreFamilyDirForTesting needs an absolute dir, got %q", absDir)
	}
	coreFamilyMu.Lock()
	coreFamilyExtra = append(coreFamilyExtra, absDir)
	coreFamilyMu.Unlock()
	t.Cleanup(func() {
		coreFamilyMu.Lock()
		defer coreFamilyMu.Unlock()
		coreFamilyExtra = slices.DeleteFunc(coreFamilyExtra, func(d string) bool { return d == absDir })
	})
}
