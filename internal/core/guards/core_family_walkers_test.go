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
//     two directories is on dirListingAllowlist with the reason it does not list
//     core sources. A new call is red until it is either re-pointed or listed.
//   - TestCoreWalkersSeeEveryCoreFamilyFile: a directory added to the family
//     shows up in coreFamilySources next to every internal/core source file.
//
// What this does not check: recursive filepath.WalkDir walkers. Those rooted at
// internal/core (or the repo) already see subpackages of internal/core; one
// rooted at internal/core does NOT see a leaf extracted to internal/<leaf>, which
// is why srcpath's registry comment asks the first such extraction to re-point
// them. Guards outside these two directories (server/http, internal/statemap)
// are not scanned.

// dirListingAllowlist: "<dir>/<file>:<enclosing func>" -> why the listing there
// is not a listing of core sources. Exact: a stale entry fails.
var dirListingAllowlist = map[string]string{
	"internal/core/besteffort_callsite_guard_test.go:beScanDir": "lists a synthetic fixture dir or a mutated copy of " +
		"the family; the real scan is beScanCore (srcpath.CoreFamilyGoFiles)",
	"internal/core/cross_replica_forced_interleaving_test.go:g5SeedFile":      "fuzz seed files under testdata/fuzz-pending",
	"internal/core/cross_replica_forced_interleaving_test.go:g5PendingIssues": "fuzz seed dirs under testdata/fuzz-pending",
	"internal/core/exempt_ledger_review_test.go:discoverExemptLedgers":        "ledger *.tsv files under docs/",
	"internal/core/fuzz_cross_replica_invariants_pending_seeds_test.go:TestPendingSeedsPromotedAfterFix": "fuzz " +
		"seed dirs under testdata/fuzz-pending",
	"internal/core/hook_storage_selftest_test.go:TestNoWholeStorageEmbeddingInCoreTests": "lists core's TEST files, not its sources " +
		"(CORE-TESTKIT-1 re-points it when the doubles move)",
	"internal/core/secret_nodes_soft_delete_guard_test.go:TestSecretNodesSoftDelete_MutationKillsPredicate": "copies " +
		"internal/storage/store, not core",
	"internal/core/guards/core_clusters_guard_test.go:readClusters":                          "CLUSTERS.d/*.txt",
	"internal/core/guards/core_clusters_guard_test.go:TestEveryCoreFileHasOneCluster":        "R4 is about package core itself, not the family",
	"internal/core/guards/core_family_walkers_test.go:dirListingSites":                       "lists the test files this guard scans",
	"internal/core/guards/core_family_walkers_test.go:TestCoreWalkersSeeEveryCoreFamilyFile": "the expected side of the coverage check",
	"internal/core/guards/ledger_fragments_test.go:readLedgerRows":                           "ledger fragment *.tsv files",
	"internal/core/guards/named_lock_order_static_test.go:namedLockStorageSources": "internal/core/storage and " +
		"internal/storage/store; the core part comes from coreFamilySources",
	"internal/core/guards/package_stays_light_guard_test.go:TestGuardsPackageStaysLight": "this guards package's own files",
	"internal/core/guards/rotation_executor_registry_exhaustiveness_test.go:discoverRotationExecutorConstructors": "internal/rotation " +
		"(and a synthetic dir), not core",
}

var dirListingFuncs = map[string]bool{"ReadDir": true, "Glob": true, "ParseDir": true, "Readdir": true, "Readdirnames": true}

// dirListingSites returns "<rel>:<enclosing func>" for every directory-listing
// call in the _test.go files directly in each of dirs (repository-relative).
func dirListingSites(root string, dirs []string) (map[string]int, error) {
	sites := map[string]int{}
	fset := token.NewFileSet()
	for _, dir := range dirs {
		entries, err := os.ReadDir(filepath.Join(root, filepath.FromSlash(dir)))
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			rel := dir + "/" + e.Name()
			f, err := parser.ParseFile(fset, filepath.Join(root, filepath.FromSlash(rel)), nil, 0)
			if err != nil {
				return nil, err
			}
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
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
	return sites, nil
}

func dirListingViolations(sites map[string]int, allow map[string]string) []string {
	var msgs []string
	for _, k := range slices.Sorted(maps.Keys(sites)) {
		if _, ok := allow[k]; !ok {
			msgs = append(msgs, fmt.Sprintf("%s lists a directory itself (%d call(s)). If it lists internal/core's sources, use "+
				"coreFamilySources(t) / srcpath.CoreFamilyGoFiles so a file moved out of core stays covered (ADR-121 R5); "+
				"otherwise add it to dirListingAllowlist with the reason", k, sites[k]))
		}
	}
	for k := range allow {
		if _, ok := sites[k]; !ok {
			msgs = append(msgs, fmt.Sprintf("dirListingAllowlist entry %s matches no listing call: remove it", k))
		}
	}
	slices.Sort(msgs)
	return msgs
}

func TestNoAdHocCoreDirListing(t *testing.T) {
	t.Parallel()
	sites, err := dirListingSites(srcpath.RepoRoot(), []string{"internal/core", "internal/core/guards"})
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) < 5 {
		t.Fatalf("found only %d listing sites: the scan is broken", len(sites))
	}
	for _, msg := range dirListingViolations(sites, dirListingAllowlist) {
		t.Error(msg)
	}
	for k, why := range dirListingAllowlist {
		if strings.TrimSpace(why) == "" {
			t.Errorf("dirListingAllowlist entry %s has no reason", k)
		}
	}
}

func TestDirListingViolations_SelfTest(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"internal/core/a_test.go": "package core\nimport \"os\"\nfunc walk() { os.ReadDir(\".\") }\n" +
			"func fixture(d string) { f, _ := os.Open(d); f.Readdirnames(0) }\n",
		"internal/core/guards/b_test.go": "package guards\nimport \"path/filepath\"\nfunc TestX() { filepath.Glob(\"../*.go\") }\n",
		"internal/core/guards/c.go":      "package guards\nimport \"os\"\nfunc prod() { os.ReadDir(\"..\") }\n",
	})
	sites, err := dirListingSites(root, []string{"internal/core", "internal/core/guards"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"internal/core/a_test.go:walk": 1, "internal/core/a_test.go:fixture": 1, "internal/core/guards/b_test.go:TestX": 1}
	if fmt.Sprint(sites) != fmt.Sprint(want) {
		t.Fatalf("sites = %v, want %v (non-test files are not scanned)", sites, want)
	}
	allow := map[string]string{"internal/core/a_test.go:fixture": "synthetic dir", "internal/core/gone_test.go:x": "stale"}
	msgs := dirListingViolations(sites, allow)
	if len(msgs) != 3 || !strings.Contains(msgs[0], "gone_test.go:x matches no listing call") ||
		!strings.HasPrefix(msgs[1], "internal/core/a_test.go:walk lists a directory itself") ||
		!strings.HasPrefix(msgs[2], "internal/core/guards/b_test.go:TestX lists") {
		t.Fatalf("unlisted walkers and stale entries must be red: %v", msgs)
	}
	allow = map[string]string{"internal/core/a_test.go:fixture": "f", "internal/core/a_test.go:walk": "w", "internal/core/guards/b_test.go:TestX": "x"}
	if msgs := dirListingViolations(sites, allow); len(msgs) != 0 {
		t.Fatalf("an exact allowlist must be green: %v", msgs)
	}
}

// TestCoreWalkersSeeEveryCoreFamilyFile adds a probe directory to the core
// family and checks that coreFamilySources (the lister every converted guard
// here uses) returns its file together with every internal/core source file.
// Not parallel: AddCoreFamilyDirForTesting changes what every guard sees while
// it runs, and parallel tests only start after the sequential ones finish.
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
