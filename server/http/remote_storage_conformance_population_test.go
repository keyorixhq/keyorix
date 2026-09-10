// remote_storage_conformance_population_test.go — #1808 tranche selection,
// reporting, AND (as of the gate added to close #1808) enforcement: derives
// (a) every real (non-stub) *RemoteStorage method and (b) which of those
// already have a TestConformance_ test, both mechanically, so "what's left"
// is never a hand-maintained list, then fails the build when an uncovered
// method has no declared exclusion. See TestConformanceCoverageIsCompleteOrDeclared.
//
// What this gate does NOT verify: that a TestConformance_ test exists for a
// method says nothing about whether it is a GOOD test, or which of #1808's
// seven defect classes it actually exercises. A green run here must not be
// read as "all seven defect classes are covered for this method" — only that
// some conformance test naming it exists. Defect-class coverage is a
// per-method judgment call made when the test is written, not something this
// mechanical AST scan can check.
//
// Why this duplicates internal/storage/store's AST-scan logic instead of
// importing it: Go test files (_test.go) are never importable across package
// boundaries, and internal/storage/store's population/stub-scan functions
// (receiverMethods, actualRemoteUnsupportedStubs, realProxyMethods) live only
// in its own _test.go files — there is no non-test symbol to import. Promoting
// them into a shared, non-test package was considered and deliberately NOT
// done here: it would either (a) add go/ast+go/parser as a real dependency of
// internal/storage/store's production build, or (b) require a new shared
// package whose design deserves its own review, not a side effect of one
// conformance tranche. Flagged as a real follow-up, not solved here.
//
// This is therefore a DELIBERATE, MINIMAL duplication of that package's exact
// reachability definition (does a *RemoteStorage method's body, followed
// transitively through same-package calls, ever reach <x>.client.<Verb>(...)),
// pointed at internal/storage/store's real source directory via runtime.Caller
// rather than a hardcoded path, so it still works regardless of how `go test`
// is invoked. If internal/storage/store's stub-signaling shapes change (a 6th
// shape, say), THIS file must be updated in lockstep — there is no automatic
// sync between the two copies. TestReportConformancePopulation's own output is
// the way to notice drift: if its real-proxy count stops matching
// internal/storage/store's own TestReportRemoteStorageProxyPopulation count,
// investigate before trusting either.
package http

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// conformancePopMethodInfo mirrors internal/storage/store's methodInfo — just
// enough to report findings against real source locations.
type conformancePopMethodInfo struct {
	Name string
	File string
	Line int
}

// conformancePopRepoRoot resolves the repository root relative to THIS test
// file's own location (not the process cwd) — same pattern as
// permission_sweep_test.go's permissionSweepRepoRoot, so this works regardless
// of how `go test` is invoked.
func conformancePopRepoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller must resolve this test file's path")
	}
	// this file lives at server/http/remote_storage_conformance_population_test.go
	root, err := filepath.Abs(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	if err != nil {
		t.Fatalf("resolving repo root: %v", err)
	}
	return root
}

func conformancePopStoreDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(conformancePopRepoRoot(t), "internal", "storage", "store")
}

// conformancePopStubSourceFiles mirrors remoteStorageStubSourceFiles: every
// non-test .go file in dir starting with "remote_" or named "entry.go" — the
// only files that can declare a *RemoteStorage method (see
// internal/storage/store/remote_unsupported_completeness_test.go's own doc
// comment; that package's TestPopulationMatchesStubScannerFileList guards this
// assumption on ITS side, this copy inherits the same assumption).
func conformancePopStubSourceFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	var files []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		if strings.HasPrefix(name, "remote_") || name == "entry.go" {
			files = append(files, name)
		}
	}
	sort.Strings(files)
	return files
}

// conformancePopExprString mirrors internal/storage/store's exprString: a
// minimal AST-expression-to-string renderer for receiver/selector types.
func conformancePopExprString(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return "*" + conformancePopExprString(t.X)
	case *ast.SelectorExpr:
		return conformancePopExprString(t.X) + "." + t.Sel.Name
	default:
		return ""
	}
}

// conformancePopActualRemoteUnsupportedStubs mirrors
// internal/storage/store's actualRemoteUnsupportedStubs EXACTLY: a
// *RemoteStorage method is stub-shaped if its body, followed transitively
// through same-package method AND package-level helper calls, never reaches
// a <x>.client.<Verb>(...) selector call. Structural, not text-pattern based
// — see that function's own doc comment for why (five independently-discovered
// stub-signaling shapes, a sixth would be invisible to any regex).
func conformancePopActualRemoteUnsupportedStubs(t *testing.T, dir string) map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	funcs := map[string]*ast.FuncDecl{}
	rsMethods := map[string]bool{}

	for _, name := range conformancePopStubSourceFiles(t, dir) {
		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			funcs[fn.Name.Name] = fn
			if fn.Recv != nil && len(fn.Recv.List) > 0 && conformancePopExprString(fn.Recv.List[0].Type) == "*RemoteStorage" {
				rsMethods[fn.Name.Name] = true
			}
		}
	}

	visiting := map[string]bool{}
	memo := map[string]bool{}
	var reachesClient func(name string) bool
	reachesClient = func(name string) bool {
		if v, ok := memo[name]; ok {
			return v
		}
		if visiting[name] {
			return false
		}
		visiting[name] = true
		defer delete(visiting, name)

		fn, ok := funcs[name]
		if !ok || fn.Body == nil {
			memo[name] = false
			return false
		}
		found := false
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if found {
				return false
			}
			switch expr := n.(type) {
			case *ast.SelectorExpr:
				if outer, ok := expr.X.(*ast.SelectorExpr); ok && conformancePopExprString(outer.Sel) == "client" {
					found = true
					return false
				}
				if callee := expr.Sel.Name; callee != name && funcs[callee] != nil {
					if reachesClient(callee) {
						found = true
						return false
					}
				}
			case *ast.CallExpr:
				if ident, ok := expr.Fun.(*ast.Ident); ok {
					if callee := ident.Name; callee != name && funcs[callee] != nil {
						if reachesClient(callee) {
							found = true
							return false
						}
					}
				}
			}
			return true
		})
		memo[name] = found
		return found
	}

	found := map[string]bool{}
	for name := range rsMethods {
		if !reachesClient(name) {
			found[name] = true
		}
	}
	return found
}

// conformancePopReceiverMethods mirrors internal/storage/store's
// receiverMethods: every top-level method declared on the given pointer
// receiver, across EVERY non-test .go file in dir (not just the stub-source
// subset) — a full re-scan, matching that function's own reasoning for why
// this must be independent of conformancePopStubSourceFiles.
func conformancePopReceiverMethods(t *testing.T, dir, receiver string) map[string]conformancePopMethodInfo {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}

	out := map[string]conformancePopMethodInfo{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || len(fn.Recv.List) == 0 {
				continue
			}
			if conformancePopExprString(fn.Recv.List[0].Type) != receiver {
				continue
			}
			pos := fset.Position(fn.Pos())
			out[fn.Name.Name] = conformancePopMethodInfo{Name: fn.Name.Name, File: name, Line: pos.Line}
		}
	}
	return out
}

// conformancePopExported mirrors internal/storage/store's exported.
func conformancePopExported(name string) bool {
	return len(name) > 0 && name[0] >= 'A' && name[0] <= 'Z'
}

// conformancePopRealProxyMethods mirrors internal/storage/store's
// realProxyMethods: every EXPORTED *RemoteStorage method that is not
// structurally a stub. This is #1808's whole-effort denominator.
func conformancePopRealProxyMethods(t *testing.T) map[string]conformancePopMethodInfo {
	t.Helper()
	dir := conformancePopStoreDir(t)
	all := conformancePopReceiverMethods(t, dir, "*RemoteStorage")
	stubs := conformancePopActualRemoteUnsupportedStubs(t, dir)

	out := map[string]conformancePopMethodInfo{}
	for name, info := range all {
		if !conformancePopExported(name) {
			continue
		}
		if stubs[name] {
			continue
		}
		out[name] = info
	}
	return out
}

// conformancePopCoveredMethods AST-scans every *_test.go file in server/http
// (this package's own directory, via the same repo-root resolution) for
// top-level func TestConformance_<Method>(t *testing.T) declarations, and
// returns the <Method> part of each name. Scanning ALL _test.go files (not
// just remote_storage_conformance_test.go by name) so a future tranche's
// tests are picked up automatically even if split across new files — the
// exact "don't hand-enumerate, don't assume a filename" discipline this
// package's own population derivation already applies to itself.
func conformancePopCoveredMethods(t *testing.T) map[string]bool {
	t.Helper()
	dir := filepath.Join(conformancePopRepoRoot(t), "server", "http")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}

	const prefix = "TestConformance_"
	fset := token.NewFileSet()
	covered := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil {
				continue
			}
			if strings.HasPrefix(fn.Name.Name, prefix) {
				method := strings.TrimPrefix(fn.Name.Name, prefix)
				covered[method] = true
			}
		}
	}
	return covered
}

// TestReportConformancePopulation is #1808's step-1 report, mirroring
// internal/storage/store's TestReportRemoteStorageProxyPopulation: the
// denominator, the covered set, and the gap between them — always passes
// (it's a report, not a gate), run with -v to see it. The uncovered list this
// prints is what "methods you could not cover, and why" must be checked
// against — never a hand-maintained list in a PR body.
//
// Also fails (this part IS a gate) if a TestConformance_ name doesn't match
// any real proxy method — the same "no third state" discipline
// internal/storage/store applies to its own population: a stale or
// mistyped TestConformance_ name should be caught immediately, not silently
// stop counting toward coverage.
func TestReportConformancePopulation(t *testing.T) {
	real := conformancePopRealProxyMethods(t)
	covered := conformancePopCoveredMethods(t)

	var coveredNames, uncoveredNames, staleNames []string
	for name := range real {
		if covered[name] {
			coveredNames = append(coveredNames, name)
		} else {
			uncoveredNames = append(uncoveredNames, name)
		}
	}
	for name := range covered {
		if _, ok := real[name]; !ok {
			staleNames = append(staleNames, name)
		}
	}
	sort.Strings(coveredNames)
	sort.Strings(uncoveredNames)
	sort.Strings(staleNames)

	t.Logf("=== #1808 conformance population report ===")
	t.Logf("real (non-stub, exported) *RemoteStorage methods: %d", len(real))
	t.Logf("covered by TestConformance_*: %d", len(coveredNames))
	for _, n := range coveredNames {
		t.Logf("  covered: %s (%s:%d)", n, real[n].File, real[n].Line)
	}
	t.Logf("NOT yet covered: %d", len(uncoveredNames))
	for _, n := range uncoveredNames {
		t.Logf("  uncovered: %s (%s:%d)", n, real[n].File, real[n].Line)
	}

	if len(staleNames) > 0 {
		t.Errorf("%d TestConformance_* test(s) name a method that is not a real (non-stub, exported) "+
			"*RemoteStorage method — stale test, renamed method, or a typo: %v", len(staleNames), staleNames)
	}
}

// conformanceCoverageExclusions: real (non-stub) RemoteStorage methods deliberately
// without a TestConformance_ test, each with a written reason.
//
// EMPTY, and it started empty — #1808 reached 0 uncovered before this gate was added,
// which is the only moment a registry like this can begin with nothing to argue about.
// An entry here is a considered exception, not a backlog item: adding one should feel
// like a decision, and the reason should be something a reviewer can disagree with.
var conformanceCoverageExclusions = map[string]string{}

// TestConformanceCoverageIsCompleteOrDeclared is #1808's closing gate. Coverage was
// complete when #1808 closed; this is what keeps it that way. A newly added real proxy
// method fails here until it either gets a TestConformance_ test or an explicit,
// reasoned exclusion.
func TestConformanceCoverageIsCompleteOrDeclared(t *testing.T) {
	t.Parallel()
	real := conformancePopRealProxyMethods(t)
	covered := conformancePopCoveredMethods(t)

	if len(real) == 0 {
		t.Fatal("derived 0 real RemoteStorage methods — the scan has stopped working and " +
			"this gate is now vacuous; fix the scan, not this test")
	}

	var undeclared []string
	for name := range real {
		if covered[name] {
			continue
		}
		if _, ok := conformanceCoverageExclusions[name]; !ok {
			undeclared = append(undeclared,
				fmt.Sprintf("%s (%s:%d)", name, real[name].File, real[name].Line))
		}
	}
	sort.Strings(undeclared)
	if len(undeclared) > 0 {
		t.Errorf("%d real (non-stub) RemoteStorage method(s) have no TestConformance_ test "+
			"and no declared exclusion:\n  %s\n\n#1808 closed at 0 uncovered. Either write "+
			"the conformance test, or add an entry to conformanceCoverageExclusions with a "+
			"reason. Do not delete or skip this check to get green.",
			len(undeclared), strings.Join(undeclared, "\n  "))
	}

	// The reverse, so exclusions cannot rot — same shape as ADR-074's CheckPartition.
	for name, reason := range conformanceCoverageExclusions {
		if _, isReal := real[name]; !isReal {
			t.Errorf("conformanceCoverageExclusions names %q, which is not a real "+
				"(non-stub, exported) RemoteStorage method — it was renamed, deleted, or "+
				"became a stub. Remove the entry.", name)
			continue
		}
		if covered[name] {
			t.Errorf("conformanceCoverageExclusions still excludes %s (%q), but it now HAS "+
				"a TestConformance_ test — remove the entry.", name, reason)
		}
	}
}
