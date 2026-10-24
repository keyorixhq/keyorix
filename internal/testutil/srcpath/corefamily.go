package srcpath

import (
	"bufio"
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path"
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
// The registry is DATA, not Go: one row per file in corefamily.d (README.md
// there). An extraction PR adds one file, corefamily.d/<leaf>.tsv, with kind
// extracted (CLAUDE.md, "Test registry tables": one file per entry). It is data
// so that no Go string literal in this package's non-test code names a core
// directory: scripts/ci/select-affected.py rule 3 would otherwise make srcpath a
// CODE seed for every internal/core change and re-test every package whose
// tests import srcpath (PR #3695 review, F5). Keep it that way: do not write a
// core-family path as a literal (or a quoted path in a comment, which the
// selector's literal scan also reads) in a non-test file of this package.
//
// Registering a dir OUTSIDE internal/core also needs a look at the WalkDir
// guards rooted at internal/core: they recurse, so they see subpackages of
// internal/core, but not internal/<leaf>.

//go:embed corefamily.d/*.tsv
var coreFamilyData embed.FS

// coreFamilyRegistry is the parsed corefamily.d: the core dir, the test-only
// dirs and the extracted dirs (dir -> reason), all repository-relative.
type coreFamilyRegistry struct {
	core      string
	testOnly  []string
	extracted map[string]string
}

var coreFamily = mustLoadCoreFamily(coreFamilyData, "corefamily.d")

// CoreDir is internal/core, relative to the repository root (the core row of
// corefamily.d). Treat it as a constant.
var CoreDir = coreFamily.core

// CoreTestOnlyDirs are the packages ADR-116 creates for tests only
// (decision 2): no production file may import them (R3, internal/core/guards)
// and internal/core's production closure must not contain them (R2,
// internal/core/ports). Repository-relative, sorted; they need not exist yet.
// The testonly rows of corefamily.d.
var CoreTestOnlyDirs = slices.Clone(coreFamily.testOnly)

func mustLoadCoreFamily(fsys fs.FS, dir string) coreFamilyRegistry {
	reg, err := loadCoreFamily(fsys, dir)
	if err != nil {
		panic("srcpath: " + err.Error())
	}
	return reg
}

// loadCoreFamily parses every *.tsv in dir: exactly one row per file, three
// tab-separated fields (kind, dir, reason), a clean repository-relative dir,
// no dir twice, exactly one core row, and every other dir distinct from it.
func loadCoreFamily(fsys fs.FS, dir string) (coreFamilyRegistry, error) {
	reg := coreFamilyRegistry{extracted: map[string]string{}}
	names, err := fs.Glob(fsys, path.Join(dir, "*.tsv"))
	if err != nil {
		return reg, err
	}
	if len(names) == 0 {
		return reg, fmt.Errorf("core family registry %s is empty", dir)
	}
	seen := map[string]string{}
	for _, name := range names {
		b, err := fs.ReadFile(fsys, name)
		if err != nil {
			return reg, err
		}
		var rows [][]string
		sc := bufio.NewScanner(strings.NewReader(string(b)))
		for sc.Scan() {
			line := strings.TrimRight(sc.Text(), "\r")
			if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
				continue
			}
			rows = append(rows, strings.Split(line, "\t"))
		}
		if len(rows) != 1 {
			return reg, fmt.Errorf("%s: want exactly one row, got %d", name, len(rows))
		}
		row := rows[0]
		if len(row) != 3 || row[2] == "" {
			return reg, fmt.Errorf("%s: want kind<TAB>dir<TAB>reason, got %q", name, strings.Join(row, "|"))
		}
		kind, rel, reason := row[0], row[1], row[2]
		if rel == "" || filepath.IsAbs(rel) || path.Clean(rel) != rel || strings.HasPrefix(rel, "..") || strings.Contains(rel, "\\") {
			return reg, fmt.Errorf("%s: dir %q must be a clean, slash-separated repository-relative path", name, rel)
		}
		if prev, dup := seen[rel]; dup {
			return reg, fmt.Errorf("%s: dir %s is also registered by %s", name, rel, prev)
		}
		seen[rel] = name
		switch kind {
		case "core":
			if reg.core != "" {
				return reg, fmt.Errorf("%s: a second core row (%s)", name, rel)
			}
			reg.core = rel
		case "testonly":
			reg.testOnly = append(reg.testOnly, rel)
		case "extracted":
			reg.extracted[rel] = reason
		default:
			return reg, fmt.Errorf("%s: unknown kind %q (core, testonly or extracted)", name, kind)
		}
	}
	if reg.core == "" {
		return reg, fmt.Errorf("core family registry %s has no core row", dir)
	}
	slices.Sort(reg.testOnly)
	return reg, nil
}

var (
	coreFamilyMu    sync.Mutex
	coreFamilyExtra []string // absolute dirs added by AddCoreFamilyDirForTesting
)

// CoreFamilyExtractedDirs returns the registered extracted package directories,
// repository-relative and sorted. internal/core itself is not in the list.
func CoreFamilyExtractedDirs() []string {
	dirs := make([]string, 0, len(coreFamily.extracted))
	for rel := range coreFamily.extracted {
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
