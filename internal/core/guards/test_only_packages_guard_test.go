package guards

import (
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

// R3 of ADR-121 (INV-CORE-package-boundaries): the test-only packages
// (srcpath.CoreTestOnlyDirs: internal/core/coretests, the storagetest kit) are
// imported from _test.go files only, and so is every package under them. A production import would link test
// doubles into a shipped binary and, for core, put them in its closure.
//
// What this does not check: files excluded by build constraints are still
// scanned (stricter, not looser); generated or vendored trees under testdata,
// node_modules, vendor and dot-directories are skipped. internal/core's own
// production closure is also checked by go list in internal/core/ports (R2).

// testOnlyImportViolations walks root and returns one message per non-test .go
// file importing one of the test-only packages (module-relative paths) or a
// package under one (storagetest/fakes is test-only too).
func testOnlyImportViolations(root string, testOnly []string) ([]string, int, error) {
	banned := make([]string, 0, len(testOnly))
	for _, p := range testOnly {
		banned = append(banned, "github.com/keyorixhq/keyorix/"+p)
	}
	isBanned := func(p string) bool {
		return slices.ContainsFunc(banned, func(b string) bool { return p == b || strings.HasPrefix(p, b+"/") })
	}
	var msgs []string
	scanned := 0
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if path != root && (strings.HasPrefix(name, ".") || name == "testdata" || name == "node_modules" || name == "vendor") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		scanned++
		f, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if perr != nil {
			return fmt.Errorf("parse %s: %w", path, perr)
		}
		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if isBanned(p) {
				rel, _ := filepath.Rel(root, path)
				msgs = append(msgs, fmt.Sprintf("%s (a production file) imports %s, which is test-only (ADR-121 R3): "+
					"import it from a _test.go file", filepath.ToSlash(rel), p))
			}
		}
		return nil
	})
	slices.Sort(msgs)
	return msgs, scanned, err
}

func TestTestOnlyPackagesNotImportedByProduction(t *testing.T) {
	t.Parallel()
	msgs, scanned, err := testOnlyImportViolations(srcpath.RepoRoot(), srcpath.CoreTestOnlyDirs)
	if err != nil {
		t.Fatal(err)
	}
	if scanned < 1000 {
		t.Fatalf("scanned only %d production files: wrong root", scanned)
	}
	for _, msg := range msgs {
		t.Error(msg)
	}
}

func TestTestOnlyImportViolations_SelfTest(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	const kit = `"github.com/keyorixhq/keyorix/internal/core/storage/storagetest"`
	writeTree(t, root, map[string]string{
		"internal/core/x_test.go":           "package core\nimport _ " + kit + "\n",
		"internal/core/coretests/a_test.go": "package coretests\nimport _ \"github.com/keyorixhq/keyorix/internal/core/coretests\"\n",
		"internal/core/storage/s.go":        "package storage\n",
		"internal/core/testdata/fixture.go": "package fixture\nimport _ " + kit + "\n",
	})
	msgs, _, err := testOnlyImportViolations(root, srcpath.CoreTestOnlyDirs)
	if err != nil || len(msgs) != 0 {
		t.Fatalf("test files and testdata may import the kit: msgs=%v err=%v", msgs, err)
	}
	writeTree(t, root, map[string]string{"server/wire.go": "package server\nimport _ " + kit + "\n"})
	msgs, _, err = testOnlyImportViolations(root, srcpath.CoreTestOnlyDirs)
	if err != nil || len(msgs) != 1 || !strings.HasPrefix(msgs[0], "server/wire.go (a production file) imports") {
		t.Fatalf("a production import must be red: msgs=%v err=%v", msgs, err)
	}
	// PR #3695 re-review N6: a package under a test-only dir is test-only too;
	// a sibling whose name only shares the prefix is not.
	root = t.TempDir()
	writeTree(t, root, map[string]string{
		"server/fakes.go":   "package server\nimport _ \"github.com/keyorixhq/keyorix/internal/core/storage/storagetest/fakes\"\n",
		"server/sibling.go": "package server\nimport _ \"github.com/keyorixhq/keyorix/internal/core/coretestsuite\"\n",
	})
	msgs, _, err = testOnlyImportViolations(root, srcpath.CoreTestOnlyDirs)
	if err != nil || len(msgs) != 1 || !strings.HasPrefix(msgs[0], "server/fakes.go (a production file) imports") {
		t.Fatalf("a production import of a subpackage of a test-only dir must be red, a name-prefix sibling green: msgs=%v err=%v", msgs, err)
	}
}
