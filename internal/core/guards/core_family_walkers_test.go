package guards

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

// R5 of ADR-121 (INV-CORE-package-boundaries), the vacuity guard for moves: a
// guard that lists internal/core's files itself (os.ReadDir(".."), Glob("*.go"))
// silently stops seeing a file the day it moves to an extracted package, and
// stays green. Guards in internal/core and internal/core/guards therefore list
// core sources through srcpath.CoreFamilyGoFiles (coreFamilySources here), and:
//
//   - TestNoAdHocCoreDirListing: every directory-listing call (ReadDir, Glob,
//     ParseDir, Readdir, Readdirnames on any receiver) in a _test.go file of those
//     two directories or of srcpath.CoreTestOnlyDirs (coretests, storagetest) is
//     on dirListingAllowlist with the reason it does not list core sources. A new
//     call is red until it is either re-pointed or listed.
//   - TestCoreWalkersSeeEveryCoreFamilyFile: a directory added to the family
//     shows up in coreFamilySources next to every internal/core source file.
//
// What this does not check: recursive filepath.WalkDir walkers. Those rooted at
// internal/core (or the repo) already see subpackages of internal/core; one
// rooted at internal/core does NOT see a leaf extracted to internal/<leaf>, which
// is why srcpath's registry comment asks the first such extraction to re-point
// them. Guards outside these directories (server/http, internal/statemap) are
// not scanned.

// dirListingMarker, in the doc comment of a function, says why the directory
// listing(s) inside it are not a listing of core sources:
//
//	// dir-listing-ok: <reason>
//
// Inline, not a hand-kept "file:func" list, so a PR that adds, renames or moves
// a listing function carries its own justification (guard-rollout-contract.md
// rule 3). Exact: a marker on a function with no listing call, or with no
// reason, fails.
const dirListingMarker = "dir-listing-ok:"

var dirListingFuncs = map[string]bool{"ReadDir": true, "Glob": true, "ParseDir": true, "Readdir": true, "Readdirnames": true}

// dirListingSites returns "<rel>:<enclosing func>" for every directory-listing
// call in the _test.go files directly in each of dirs (repository-relative),
// and the dirListingMarker reason of every function whose doc comment has one
// (same key; "" for a marker without reason text).
// dir-listing-ok: lists the test files this guard scans
func dirListingSites(root string, dirs []string) (sites map[string]int, markers map[string]string, err error) {
	sites = map[string]int{}
	markers = map[string]string{}
	fset := token.NewFileSet()
	for _, dir := range dirs {
		entries, err := os.ReadDir(filepath.Join(root, filepath.FromSlash(dir)))
		if err != nil {
			return nil, nil, err
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			rel := dir + "/" + e.Name()
			f, err := parser.ParseFile(fset, filepath.Join(root, filepath.FromSlash(rel)), nil, parser.ParseComments)
			if err != nil {
				return nil, nil, err
			}
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				if fd.Doc != nil {
					for _, c := range fd.Doc.List {
						if _, reason, found := strings.Cut(c.Text, dirListingMarker); found {
							markers[rel+":"+fd.Name.Name] = strings.TrimSpace(reason)
						}
					}
				}
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					if call, ok := n.(*ast.CallExpr); ok {
						if sel, ok := call.Fun.(*ast.SelectorExpr); ok && dirListingFuncs[sel.Sel.Name] {
							sites[rel+":"+fd.Name.Name]++
						}
					}
					return true
				})
			}
		}
	}
	return sites, markers, nil
}

func dirListingViolations(sites map[string]int, markers map[string]string) []string {
	var msgs []string
	for _, k := range slices.Sorted(maps.Keys(sites)) {
		if _, ok := markers[k]; !ok {
			msgs = append(msgs, fmt.Sprintf("%s lists a directory itself (%d call(s)). If it lists internal/core's sources, use "+
				"coreFamilySources(t) / srcpath.CoreFamilyGoFiles so a file moved out of core stays covered (ADR-121 R5); "+
				"otherwise add a `// %s <reason>` line to the function's doc comment", k, sites[k], dirListingMarker))
		}
	}
	for k, why := range markers {
		if _, ok := sites[k]; !ok {
			msgs = append(msgs, fmt.Sprintf("%s has a dir-listing marker but no listing call: remove the marker", k))
		} else if strings.TrimSpace(why) == "" {
			msgs = append(msgs, fmt.Sprintf("%s has a dir-listing marker with no reason", k))
		}
	}
	slices.Sort(msgs)
	return msgs
}

func TestNoAdHocCoreDirListing(t *testing.T) {
	t.Parallel()
	sites, markers, err := dirListingSites(srcpath.RepoRoot(), append([]string{"internal/core", "internal/core/guards"}, srcpath.CoreTestOnlyDirs...))
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) < 5 {
		t.Fatalf("found only %d listing sites: the scan is broken", len(sites))
	}
	for _, msg := range dirListingViolations(sites, markers) {
		t.Error(msg)
	}
}

func TestDirListingViolations_SelfTest(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"internal/core/a_test.go": "package core\nimport \"os\"\nfunc walk() { os.ReadDir(\".\") }\n" +
			"// dir-listing-ok: synthetic dir\nfunc fixture(d string) { f, _ := os.Open(d); f.Readdirnames(0) }\n" +
			"// dir-listing-ok: marker on a func that lists nothing\nfunc gone() {}\n",
		"internal/core/guards/b_test.go": "package guards\nimport \"path/filepath\"\nfunc TestX() { filepath.Glob(\"../*.go\") }\n",
		"internal/core/guards/c.go":      "package guards\nimport \"os\"\nfunc prod() { os.ReadDir(\"..\") }\n",
	})
	sites, markers, err := dirListingSites(root, []string{"internal/core", "internal/core/guards"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"internal/core/a_test.go:walk": 1, "internal/core/a_test.go:fixture": 1, "internal/core/guards/b_test.go:TestX": 1}
	if fmt.Sprint(sites) != fmt.Sprint(want) {
		t.Fatalf("sites = %v, want %v (non-test files are not scanned)", sites, want)
	}
	// Red: an unmarked listing (walk, TestX) and a stale marker (gone).
	msgs := dirListingViolations(sites, markers)
	if len(msgs) != 3 || !strings.HasPrefix(msgs[0], "internal/core/a_test.go:gone has a dir-listing marker but no listing call") ||
		!strings.HasPrefix(msgs[1], "internal/core/a_test.go:walk lists a directory itself") ||
		!strings.HasPrefix(msgs[2], "internal/core/guards/b_test.go:TestX lists") {
		t.Fatalf("unmarked listings and stale markers must be red: %v", msgs)
	}
	// Red: a marker with no reason text.
	noReason := map[string]string{"internal/core/a_test.go:fixture": "", "internal/core/a_test.go:walk": "w", "internal/core/guards/b_test.go:TestX": "x"}
	if msgs := dirListingViolations(sites, noReason); len(msgs) != 1 || !strings.Contains(msgs[0], "no reason") {
		t.Fatalf("a marker without a reason must be red: %v", msgs)
	}
	// Green: exactly one marker per listing function.
	exact := map[string]string{"internal/core/a_test.go:fixture": "f", "internal/core/a_test.go:walk": "w", "internal/core/guards/b_test.go:TestX": "x"}
	if msgs := dirListingViolations(sites, exact); len(msgs) != 0 {
		t.Fatalf("exact markers must be green: %v", msgs)
	}
}

// TestCoreWalkersSeeEveryCoreFamilyFile adds a probe directory to the core
// family and checks that coreFamilySources (the lister every converted guard
// here uses) returns its file together with every internal/core source file.
// Not parallel: AddCoreFamilyDirForTesting changes what every guard sees while
// it runs, and parallel tests only start after the sequential ones finish.
// dir-listing-ok: the expected side of the coverage check
func TestCoreWalkersSeeEveryCoreFamilyFile(t *testing.T) {
	probe := t.TempDir()
	writeTree(t, probe, map[string]string{"probe.go": "package probe\n", "probe_test.go": "package probe\n"})
	srcpath.AddCoreFamilyDirForTesting(t, probe)

	files := coreFamilySources(t)
	if !slices.Contains(files, filepath.Join(probe, "probe.go")) {
		t.Errorf("coreFamilySources does not list a registered family dir's file: a guard using it would skip moved files")
	}
	if slices.Contains(files, filepath.Join(probe, "probe_test.go")) {
		t.Errorf("coreFamilySources must list source files only")
	}
	coreDir := filepath.Join(srcpath.RepoRoot(), filepath.FromSlash(srcpath.CoreDir))
	entries, err := os.ReadDir(coreDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		n := e.Name()
		if !e.IsDir() && strings.HasSuffix(n, ".go") && !strings.HasSuffix(n, "_test.go") && !slices.Contains(files, filepath.Join(coreDir, n)) {
			t.Errorf("coreFamilySources misses internal/core/%s", n)
		}
	}
	if got := srcpath.CoreFamilyRel(filepath.Join(probe, "probe.go")); got == "probe.go" {
		t.Errorf("a family file outside internal/core must not be keyed by its bare name (got %q)", got)
	}
}
