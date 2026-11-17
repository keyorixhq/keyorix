package boundedworksweep

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/boundedwork"
)

// TestBoundedWorkSweep_EveryTargetJudgesASeed holds that every committed
// bounded-work target can actually reach a verdict: at least one of its seeds,
// scaled by the target's own scaler and measured under its own Config, must be
// above the oracle's floors (Verdict.Judged). A target that is "not judged" on
// every seed is a green check that guards nothing: it cannot fire whatever the
// library does. That was the state of json.NewDecoder, json.Unmarshal,
// json.Valid, the json RoundTrip decode arm and yaml/v2 NewDecoder at
// ce613e13 (review REVIEW-4284-DEEP-1, MEDIUM-1).
//
// The targets come from bwgen's registry (bwTargets), the same values the Fuzz
// functions run, so this test cannot drift from them; it also checks that every
// Fuzz function in the package is registered.
func TestBoundedWorkSweep_EveryTargetJudgesASeed(t *testing.T) {
	registered := map[string]bool{}
	for _, bt := range bwTargets {
		registered[bt.fuzz] = true
	}
	for _, name := range fuzzFuncs(t) {
		if !registered[name] {
			t.Errorf("%s is not in bwTargets: every bounded-work Fuzz target must be a registered bwgen target", name)
		}
	}
	if len(bwTargets) == 0 {
		t.Fatal("no registered bounded-work targets")
	}

	for _, bt := range bwTargets {
		var reasons []string
		judged := false
		for _, s := range bwSeeds {
			v := boundedwork.Analyze(bt.label, []byte(s), bt.scale, bt.call, bt.cfg)
			if v.Judged {
				judged = true
				t.Logf("%s: judged on seed %q: %s", bt.fuzz, s, v.Reason)
				break
			}
			reasons = append(reasons, s+": "+v.Reason)
		}
		if !judged {
			t.Errorf("%s: no seed reaches a verdict, the target can never fire:\n  %s",
				bt.fuzz, strings.Join(reasons, "\n  "))
		}
	}
}

// fuzzFuncs returns the names of the Fuzz functions declared in this package's
// test files.
func fuzzFuncs(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	fset := token.NewFileSet()
	var names []string
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, e.Name(), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", e.Name(), err)
		}
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && strings.HasPrefix(fd.Name.Name, "Fuzz") {
				names = append(names, fd.Name.Name)
			}
		}
	}
	slices.Sort(names)
	if len(names) == 0 {
		t.Fatal("found no Fuzz functions in the package")
	}
	return names
}
