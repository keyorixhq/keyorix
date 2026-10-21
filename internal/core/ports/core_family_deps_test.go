package ports

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

// R1 and R2 of ADR-116 (docs/adr-116-core-package-split.md,
// INV-CORE-package-boundaries). Same `go list -deps` mechanism as
// heavy_deps_guard_test.go, production closures only (default build tags,
// test files excluded).
//
// The core family registry (which packages were extracted from internal/core)
// lives in internal/testutil/srcpath (one corefamily_<leaf>.go file per package)
// because the source-scanning guards in internal/core and internal/core/guards
// read it too; a registry declared in this package's test files would be
// invisible to them.

// coreProductionKeyorixDeps is the exact set of keyorix packages in
// `go list -deps ./internal/core` (internal/core itself excluded). A PR that adds
// or removes a keyorix import anywhere in core's production closure edits this
// list, so the change is reviewed (R2). An extraction PR adds its leaf here.
var coreProductionKeyorixDeps = []string{
	"internal/besteffort",
	"internal/core/certparse",
	"internal/core/dsn",
	"internal/core/ports",
	"internal/core/rules",
	"internal/core/storage",
	"internal/csvsafe",
	"internal/i18n",
	"internal/identity",
	"internal/logging",
	"internal/netutil",
	"internal/protectedmetrics",
	"internal/secretenv",
	"internal/secrettemplate",
	"internal/securefiles",
	"internal/storage/models",
	"pkg/licenseverify",
	"pkg/trust",
}

// coreTestOnlyPackages may only ever be imported from _test.go files
// (ADR-116 decision 2). They do not exist yet; the check is ready for them.
// R3 (internal/core/guards) checks the same list over every production file
// of the repository; this is the closure-level check for internal/core.
var coreTestOnlyPackages = []string{
	"internal/core/coretests",
	"internal/core/storage/storagetest",
}

// importsCoreViolations returns one message per family package whose
// production closure in graph contains internal/core, with the import chain.
func importsCoreViolations(graph map[string][]string, family []string) []string {
	var msgs []string
	for _, pkg := range family {
		if chain := chainTo(graph, pkg, coreImportPath); chain != nil {
			msgs = append(msgs, fmt.Sprintf("%s was extracted from internal/core (core family) but imports it: %s. "+
				"An extracted package must not import internal/core (ADR-116 R1); depend on internal/core/ports or a leaf instead",
				pkg, strings.Join(chain, " -> ")))
		}
	}
	return msgs
}

// keyorixDepsDiff compares the keyorix packages in graph (minus root) with
// want (module-relative paths) and returns the unexpected and the missing ones.
func keyorixDepsDiff(graph map[string][]string, root string, want []string) (extra, missing []string) {
	got := map[string]bool{}
	for dep := range graph {
		if dep != root && strings.HasPrefix(dep, keyorixPrefix) {
			got[strings.TrimPrefix(dep, keyorixPrefix)] = true
		}
	}
	for _, w := range want {
		if !got[w] {
			missing = append(missing, w)
		}
		delete(got, w)
	}
	extra = slices.Sorted(maps.Keys(got))
	return extra, missing
}

// TestCoreFamilyNeverImportsCore is R1: no registered extracted package has
// internal/core in its production closure. With no package registered yet it
// checks nothing and says so.
func TestCoreFamilyNeverImportsCore(t *testing.T) {
	dirs := srcpath.CoreFamilyExtractedDirs()
	if len(dirs) == 0 {
		t.Log("no package registered in the core family yet (internal/testutil/srcpath/corefamily_*.go): nothing to check")
		return
	}
	for _, rel := range dirs {
		pkg := keyorixPrefix + rel
		for _, msg := range importsCoreViolations(listImportGraph(t, pkg), []string{pkg}) {
			t.Error(msg)
		}
	}
}

// TestCoreKeyorixDepsMatchAllowlist is R2: the keyorix packages in core's
// production closure are exactly coreProductionKeyorixDeps, and no test-only
// package is among them.
func TestCoreKeyorixDepsMatchAllowlist(t *testing.T) {
	graph := coreClosure(t)
	for _, p := range coreTestOnlyPackages {
		if chain := chainTo(graph, coreImportPath, keyorixPrefix+p); chain != nil {
			t.Errorf("%s is test-only (ADR-116) but is in internal/core's production closure: %s", p, strings.Join(chain, " -> "))
		}
	}
	extra, missing := keyorixDepsDiff(graph, coreImportPath, coreProductionKeyorixDeps)
	for _, e := range extra {
		chain := chainTo(graph, coreImportPath, keyorixPrefix+e)
		t.Errorf("new keyorix package in internal/core's production closure: %s (chain: %s). "+
			"If the import is intended, add it to coreProductionKeyorixDeps in this PR (ADR-116 R2); "+
			"an extracted leaf's internals belong under <leaf>/internal/", e, strings.Join(chain, " -> "))
	}
	for _, m := range missing {
		t.Errorf("%s is listed in coreProductionKeyorixDeps but internal/core no longer depends on it: remove it from the list", m)
	}
}

// TestCoreFamilyDeps_SelfTest runs both checks on synthetic graphs: red on a
// family package importing core (directly and through another package) and on
// a new or vanished keyorix dep, green on the corrected graphs.
func TestCoreFamilyDeps_SelfTest(t *testing.T) {
	const (
		leaf  = keyorixPrefix + "internal/anomaly"
		other = keyorixPrefix + "internal/oidcverify"
		mid   = keyorixPrefix + "internal/notify"
		rules = keyorixPrefix + "internal/core/rules"
	)
	bad := map[string][]string{
		leaf:           {coreImportPath},
		other:          {mid},
		mid:            {coreImportPath},
		coreImportPath: {rules},
		rules:          nil,
	}
	msgs := importsCoreViolations(bad, []string{leaf, other})
	if len(msgs) != 2 {
		t.Fatalf("want 2 R1 violations, got %d: %v", len(msgs), msgs)
	}
	if !strings.Contains(msgs[1], other+" -> "+mid+" -> "+coreImportPath) {
		t.Errorf("an indirect import of core must name the chain: %s", msgs[1])
	}
	good := map[string][]string{leaf: {rules}, other: nil, rules: nil, coreImportPath: {leaf}}
	if msgs := importsCoreViolations(good, []string{leaf, other}); len(msgs) != 0 {
		t.Errorf("core importing a leaf is the allowed direction: %v", msgs)
	}

	graph := map[string][]string{coreImportPath: {rules, leaf}, rules: nil, leaf: nil, "example.com/x": nil}
	extra, missing := keyorixDepsDiff(graph, coreImportPath, []string{"internal/core/rules", "internal/gone"})
	if !slices.Equal(extra, []string{"internal/anomaly"}) || !slices.Equal(missing, []string{"internal/gone"}) {
		t.Errorf("keyorixDepsDiff: extra=%v missing=%v, want [internal/anomaly] [internal/gone]", extra, missing)
	}
	extra, missing = keyorixDepsDiff(graph, coreImportPath, []string{"internal/anomaly", "internal/core/rules"})
	if len(extra)+len(missing) != 0 {
		t.Errorf("exact list must be green: extra=%v missing=%v", extra, missing)
	}
}
