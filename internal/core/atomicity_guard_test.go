// atomicity_guard_test.go — Session O's O5 repo guard: fails when a non-test
// function in internal/core makes 2+ storage writes (either c.storage.<Write>
// calls, or calls to OTHER *KeyorixCore write methods — the shape O1's
// blind-spot sweep found SetUserRoles in, invisible to a storage-only scan)
// outside a WithTransaction closure, and is not listed in
// docs/atomicity-exempt.tsv with a reviewed class and reason.
//
// This is the coordinator's txscan (scratch/txscan/main.go) and its
// corescan sibling (built during O1, not checked in), turned into a
// permanent CI-enforced guard instead of a one-off scan. Like txscan, this
// is an AST walk with no control-flow awareness: a function with two
// matching calls on MUTUALLY EXCLUSIVE branches (an if/else, a switch) is
// flagged exactly the same as one with a true sequential multi-write — O1's
// triage found this is common (11 of the original 32 txscan hits). A human
// must classify each hit; this guard only enforces that every hit HAS been
// classified and stays classified as the code changes.
package core

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var atomicityWriteVerbRe = regexp.MustCompile(`^(Create|Update|Delete|Assign|Unassign|Set|Remove|Add|Revoke|Insert|Upsert|Save|Mark|Record|Increment|Rotate|Restore|Purge|Archive|Grant|Link|Unlink|Replace|Put|Store|Clear|Reset|Enable|Disable|Lock|Unlock|Consume|Approve|Reject|Expire|Touch|Bump|Append|Move|Rename|Transfer|Finalize|Complete|Cancel|Provision|Deprovision|Patch|Activate|Deactivate|Issue|Open|Close|Withdraw)`)

type atomicityHit struct {
	fn     string // "(*KeyorixCore).Foo"
	file   string // basename, e.g. "project_members.go"
	writes []string
}

// scanAtomicityHits walks every non-test, non-generated *.go file directly
// under internal/core (not subpackages — storage/, ports/, rules/ have their
// own concerns) for funcs on *KeyorixCore or *AnomalyDetector with 2+
// storage-write or core-to-core-write calls outside WithTransaction.
func scanAtomicityHits(t *testing.T, root string) []atomicityHit {
	t.Helper()
	var hits []atomicityHit
	fset := token.NewFileSet()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("atomicity guard: cannot read %s: %v", root, err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || strings.Contains(name, "generated") {
			continue
		}
		p := filepath.Join(root, name)
		f, perr := parser.ParseFile(fset, p, nil, 0)
		if perr != nil {
			t.Fatalf("atomicity guard: cannot parse %s: %v", p, perr)
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil || fd.Recv == nil {
				continue
			}
			recvType := atomicityExprStr(fd.Recv.List[0].Type)
			if recvType != "*KeyorixCore" && recvType != "*AnomalyDetector" {
				continue
			}
			var writes []string
			var walk func(n ast.Node, inTx bool)
			walk = func(n ast.Node, inTx bool) {
				ast.Inspect(n, func(m ast.Node) bool {
					call, ok := m.(*ast.CallExpr)
					if !ok {
						return true
					}
					sel, ok := call.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					if sel.Sel.Name == "WithTransaction" {
						walk(sel.X, inTx)
						for _, a := range call.Args {
							walk(a, true)
						}
						return false
					}
					if inTx {
						return true
					}
					// c.storage.<Write>(...)
					if inner, ok := sel.X.(*ast.SelectorExpr); ok && inner.Sel.Name == "storage" {
						if atomicityWriteVerbRe.MatchString(sel.Sel.Name) {
							writes = append(writes, fmt.Sprintf("storage.%s@%d", sel.Sel.Name, fset.Position(call.Pos()).Line))
						}
						return true
					}
					// c.<Write>(...) — core-to-core write call (the SetUserRoles shape).
					if id, ok := sel.X.(*ast.Ident); ok && id.Name == "c" {
						if atomicityWriteVerbRe.MatchString(sel.Sel.Name) {
							writes = append(writes, fmt.Sprintf("%s@%d", sel.Sel.Name, fset.Position(call.Pos()).Line))
						}
					}
					return true
				})
			}
			walk(fd.Body, false)
			if len(writes) >= 2 {
				hits = append(hits, atomicityHit{
					fn:     "(" + recvType + ")." + fd.Name.Name,
					file:   name,
					writes: writes,
				})
			}
		}
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].fn < hits[j].fn })
	return hits
}

// loadAtomicityExemptions reads docs/atomicity-exempt.tsv (function\tclass\treason,
// '#'-prefixed lines and blank lines ignored) into a set of exempted function names.
func loadAtomicityExemptions(t *testing.T, path string) map[string]bool {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("atomicity guard: cannot read %s: %v", path, err)
	}
	out := map[string]bool{}
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 3 {
			t.Fatalf("atomicity guard: %s:%d: expected 3 tab-separated fields (function, class, reason), got %d: %q", path, i+1, len(fields), line)
		}
		out[fields[0]] = true
	}
	return out
}

// TestAtomicityGuard_UnclassifiedMultiWriteFunction is Session O's O5 guard:
// every internal/core function with 2+ storage/core writes outside
// WithTransaction must be a reviewed, reasoned entry in
// docs/atomicity-exempt.tsv. A hit with no entry is either a genuine new
// atomicity bug (fix it) or a function that needs its class/reason recorded
// (classify it per SESSION-O's A/B/C/D rubric and add the line) — never
// silently ignored.
func TestAtomicityGuard_UnclassifiedMultiWriteFunction(t *testing.T) {
	hits := scanAtomicityHits(t, ".")
	exempt := loadAtomicityExemptions(t, "../../docs/atomicity-exempt.tsv")

	var unclassified []string
	for _, h := range hits {
		if !exempt[h.fn] {
			unclassified = append(unclassified, fmt.Sprintf("%s (%s): %s", h.fn, h.file, strings.Join(h.writes, ", ")))
		}
	}
	if len(unclassified) > 0 {
		t.Fatalf("atomicity guard: %d function(s) with 2+ storage/core writes outside WithTransaction have no "+
			"reviewed entry in docs/atomicity-exempt.tsv. Classify each per SESSION-O's A/B/C/D rubric (A: wrap "+
			"in one transaction, don't exempt; B/C/D: add a line to docs/atomicity-exempt.tsv with the class and "+
			"a one-line reason). Unclassified:\n  %s", len(unclassified), strings.Join(unclassified, "\n  "))
	}
}

func atomicityExprStr(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.StarExpr:
		return "*" + atomicityExprStr(t.X)
	case *ast.Ident:
		return t.Name
	}
	return "?"
}
