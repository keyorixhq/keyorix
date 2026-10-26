package ports

import (
	"fmt"
	"maps"
	"path"
	"slices"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

// R1 and R2 of ADR-121 (docs/adr-121-core-package-split.md,
// INV-CORE-package-boundaries). Same `go list -deps` mechanism as
// heavy_deps_guard_test.go, production closures only (default build tags,
// test files excluded).
//
// The core family registry (which packages were extracted from internal/core)
// lives in internal/testutil/srcpath (one corefamily.d/<leaf>.tsv row per package)
// because the source-scanning guards in internal/core and internal/core/guards
// read it too; a registry declared in this package's test files would be
// invisible to them.

// coreProductionKeyorixDeps is the exact set of keyorix packages in
// `go list -deps ./internal/core` (internal/core itself excluded). A PR that adds
// or removes a keyorix import anywhere in core's production closure edits this
// list, so the change is reviewed (R2). An extraction PR adds its leaf here
// and registers it in internal/testutil/srcpath/corefamily.d
// (TestCoreDepsAfterSplitAreRegisteredLeavesGuard).
var coreProductionKeyorixDeps = []string{
	"internal/anomaly",
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
	"internal/oidcverify",
	"internal/protectedmetrics",
	"internal/secretenv",
	"internal/secrettemplate",
	"internal/securefiles",
	"internal/storage/models",
	"pkg/licenseverify",
	"pkg/trust",
}

// coreDepsBeforeSplit is coreProductionKeyorixDeps as it stood when ADR-121
// was accepted, frozen: none of these packages ever held internal/core code.
// A keyorix package that enters core's closure later is either a leaf
// extracted from core, which must be registered `extracted` in corefamily.d so
// R1 and every R5 source guard scan it, or a package that never held core
// code, which is added here in a reviewed PR that says why. PR #3695
// re-review N4: following R2's message alone let a kernel file leave core
// for a leaf no source guard scanned.
var coreDepsBeforeSplit = []string{
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

// unregisteredCoreDeps returns one message per keyorix package in graph
// (minus root) that is neither in before nor inside a registered extracted dir
// (the dir itself or a package under it, such as <leaf>/internal/x).
func unregisteredCoreDeps(graph map[string][]string, root string, before, extracted []string) []string {
	extra, _ := keyorixDepsDiff(graph, root, before)
	var msgs []string
	for _, dep := range extra {
		if slices.ContainsFunc(extracted, func(dir string) bool { return dep == dir || strings.HasPrefix(dep, dir+"/") }) {
			continue
		}
		msgs = append(msgs, fmt.Sprintf("%s entered internal/core's production closure after the ADR-121 split began and is not "+
			"a registered core-family leaf. If it was extracted from internal/core, add "+
			"internal/testutil/srcpath/corefamily.d/%s.tsv (kind `extracted`, ADR-121 R1/R5) so the core-family source guards scan it; "+
			"kernel files never move (ADR-121 decision 1). If it never held core code, add it to coreDepsBeforeSplit with the reason",
			dep, path.Base(dep)))
	}
	return msgs
}

// importsCoreViolations returns one message per family package whose
// production closure in graph contains internal/core, with the import chain.
func importsCoreViolations(graph map[string][]string, family []string) []string {
	var msgs []string
	for _, pkg := range family {
		if chain := chainTo(graph, pkg, coreImportPath); chain != nil {
			msgs = append(msgs, fmt.Sprintf("%s was extracted from internal/core (core family) but imports it: %s. "+
				"An extracted package must not import internal/core (ADR-121 R1); depend on internal/core/ports or a leaf instead",
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

// TestCoreFamilyNeverImportsCoreGuard is R1: no registered extracted package
// has internal/core in its production closure. With no package registered yet
// it checks nothing and says so. (The Guard suffix puts it in
// scripts/ci/run-guards.sh, so it runs on every merge-queue run.)
func TestCoreFamilyNeverImportsCoreGuard(t *testing.T) {
	dirs := srcpath.CoreFamilyExtractedDirs()
	if len(dirs) == 0 {
		t.Log("no package registered in the core family yet (internal/testutil/srcpath/corefamily.d): nothing to check")
		return
	}
	for _, rel := range dirs {
		pkg := keyorixPrefix + rel
		for _, msg := range importsCoreViolations(listImportGraph(t, pkg), []string{pkg}) {
			t.Error(msg)
		}
	}
}

// TestCoreKeyorixDepsMatchAllowlistGuard is R2: the keyorix packages in core's
// production closure are exactly coreProductionKeyorixDeps, and no test-only
// package is among them.
func TestCoreKeyorixDepsMatchAllowlistGuard(t *testing.T) {
	graph := coreClosure(t)
	for _, p := range srcpath.CoreTestOnlyDirs {
		if chain := chainTo(graph, coreImportPath, keyorixPrefix+p); chain != nil {
			t.Errorf("%s is test-only (ADR-121) but is in internal/core's production closure: %s", p, strings.Join(chain, " -> "))
		}
	}
	extra, missing := keyorixDepsDiff(graph, coreImportPath, coreProductionKeyorixDeps)
	for _, e := range extra {
		chain := chainTo(graph, coreImportPath, keyorixPrefix+e)
		t.Errorf("new keyorix package in internal/core's production closure: %s (chain: %s). "+
			"If the import is intended, add it to coreProductionKeyorixDeps in this PR (ADR-121 R2). "+
			"If it is a leaf extracted from internal/core, also register it as `extracted` in "+
			"internal/testutil/srcpath/corefamily.d/<leaf>.tsv, or the core-family source guards (R5) stop scanning the moved code; "+
			"an extracted leaf's internals belong under <leaf>/internal/", e, strings.Join(chain, " -> "))
	}
	for _, m := range missing {
		t.Errorf("%s is listed in coreProductionKeyorixDeps but internal/core no longer depends on it: remove it from the list", m)
	}
}

// TestCoreDepsAfterSplitAreRegisteredLeavesGuard: every keyorix package that
// entered core's production closure after coreDepsBeforeSplit was frozen is a
// registered extracted leaf (or a package under one).
func TestCoreDepsAfterSplitAreRegisteredLeavesGuard(t *testing.T) {
	for _, msg := range unregisteredCoreDeps(coreClosure(t), coreImportPath, coreDepsBeforeSplit, srcpath.CoreFamilyExtractedDirs()) {
		t.Error(msg)
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

	// A new dep of core that is not a registered leaf is red, with the registry file named.
	sub := keyorixPrefix + "internal/anomaly/internal/score"
	graph = map[string][]string{coreImportPath: {rules, leaf, sub}, rules: nil, leaf: nil, sub: nil}
	msgs = unregisteredCoreDeps(graph, coreImportPath, []string{"internal/core/rules"}, nil)
	if len(msgs) != 2 || !strings.Contains(msgs[0], "corefamily.d/anomaly.tsv") {
		t.Fatalf("an unregistered new dep and its subpackage must be red, naming corefamily.d/<leaf>.tsv: %v", msgs)
	}
	if msgs := unregisteredCoreDeps(graph, coreImportPath, []string{"internal/core/rules"}, []string{"internal/anomaly"}); len(msgs) != 0 {
		t.Errorf("a registered leaf and the packages under it are green: %v", msgs)
	}
	if msgs := unregisteredCoreDeps(graph, coreImportPath, []string{"internal/core/rules"}, []string{"internal/anom"}); len(msgs) != 2 {
		t.Errorf("a registered dir is matched by path element, not string prefix: %v", msgs)
	}
}
