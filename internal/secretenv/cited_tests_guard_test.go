package secretenv

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// TestCitedTestsExist fails when a comment in this package names a Test function
// that is defined nowhere in the repository (main module, cli/ and the other
// nested modules alike).
//
// Why (SEC-REVIEW-ROWS-1): this package's doc comments say which test holds a
// rule ("TestDescribeFileCopiesAgree ... hold them to the same text"). Such a
// citation is how a reader decides a rule is machine-checked; one that names no
// test is a claim with no mechanism behind it, and describe.go carried exactly
// that until this guard: TestDescribeFileCopiesAgree never existed (the copies
// are held by TestDescribeSecretFile_MatchesSecretenv and
// TestEntrypointDescribeMatchesSecretenv).
//
// It recognises a citation only as a whole identifier Test<Upper>... inside a //
// or /* */ comment of a .go file directly in internal/secretenv (this file
// excepted: it names the missing test on purpose), and a definition
// only as "func <name>(" in a *_test.go file anywhere under the repository root
// (testdata, node_modules, .git and hidden directories skipped). It does NOT check
// that the cited test asserts what the comment says, citations outside this
// package, or names written without the Test prefix; a family of subtests or of
// _Suffix variants must be cited by a real member.
func TestCitedTestsExist(t *testing.T) {
	cited := citedTestNames(t, ".")
	if len(cited) == 0 {
		t.Fatal("no Test names cited in internal/secretenv comments: the scanner is broken (this package cites several)")
	}
	defined := definedTestNames(t, repoRoot(t))
	for _, c := range cited {
		if !defined[c.name] {
			t.Errorf("%s cites %s, which is defined nowhere in the repository: name the test that holds the rule, or drop the claim", c.where, c.name)
		}
	}
}

// TestCitedTestsScanner_RedGreen calibrates both halves on a planted tree: a
// citation of a defined test passes, one of an undefined test is reported, and a
// Test name outside a comment (a string, an identifier) is not a citation.
func TestCitedTestsScanner_RedGreen(t *testing.T) {
	root := t.TempDir()
	pkg := filepath.Join(root, "pkg")
	for name, body := range map[string]string{
		"go.mod": "module planted\n",
		"pkg/a.go": "package pkg\n\n// Held by TestReal and TestGhost.\n" +
			"/* also TestBlockGhost */\nvar s = \"TestInString\"\n\nfunc TestNotAComment() {}\n",
		"other/real_test.go":       "package other\n\nimport \"testing\"\n\nfunc TestReal(t *testing.T) {}\n",
		"other/testdata/x_test.go": "package x\n\nfunc TestGhost(t *testing.T) {}\n",
	} {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var names []string
	for _, c := range citedTestNames(t, pkg) {
		names = append(names, c.name)
	}
	if want := []string{"TestBlockGhost", "TestGhost", "TestReal"}; !slices.Equal(names, want) {
		t.Fatalf("cited = %v, want %v (comments only, strings and declarations ignored)", names, want)
	}
	defined := definedTestNames(t, root)
	if !defined["TestReal"] {
		t.Error("TestReal is defined in other/real_test.go but was not found")
	}
	if defined["TestGhost"] {
		t.Error("TestGhost is defined only under testdata/, which must not count")
	}
}

type citation struct{ name, where string }

var testIdent = regexp.MustCompile(`\bTest[A-Z][A-Za-z0-9_]*`)

// citedTestNames returns the Test names cited in comments of the .go files
// directly in dir, sorted by name and deduplicated (first site kept).
func citedTestNames(t *testing.T, dir string) []citation {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	var out []citation
	fset := token.NewFileSet()
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || e.Name() == "cited_tests_guard_test.go" {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		for _, cg := range f.Comments {
			for _, c := range cg.List {
				for _, name := range testIdent.FindAllString(c.Text, -1) {
					name = strings.TrimRight(name, "_")
					if seen[name] {
						continue
					}
					seen[name] = true
					pos := fset.Position(c.Pos())
					out = append(out, citation{name: name, where: e.Name() + ":" + strconv.Itoa(pos.Line)})
				}
			}
		}
	}
	slices.SortFunc(out, func(a, b citation) int { return strings.Compare(a.name, b.name) })
	return out
}

var testFuncDecl = regexp.MustCompile(`(?m)^func (Test[A-Za-z0-9_]*)\(`)

// definedTestNames returns every Test function declared in a *_test.go file
// under root, skipping testdata, node_modules and hidden directories.
func definedTestNames(t *testing.T, root string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != root && (d.Name() == "testdata" || d.Name() == "node_modules" || strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		src, err := os.ReadFile(p) // #nosec G304 -- walking this repository's own test sources
		if err != nil {
			return err
		}
		for _, m := range testFuncDecl.FindAllSubmatch(src, -1) {
			out[string(m[1])] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
