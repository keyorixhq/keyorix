package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// toyModuleCopy copies the committed toy fixture module into a fresh temp dir
// (oraclehealth never mutates a checkout in place) and returns the copy root.
func toyModuleCopy(t *testing.T) string {
	t.Helper()
	src, err := filepath.Abs(filepath.Join("testdata", "toy"))
	if err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	if err := copyModule(src, dst); err != nil {
		t.Fatalf("copyModule: %v", err)
	}
	return dst
}

// TestCollectMutations_ToyOperators is a fast, fuzz-free check that the AST
// mutator finds the operators we rely on in the red/green proof: the comparison
// flip and the condition negation on Max's branch.
func TestCollectMutations_ToyOperators(t *testing.T) {
	root := toyModuleCopy(t)
	muts, err := collectMutations(root, root, nil)
	if err != nil {
		t.Fatalf("collectMutations: %v", err)
	}
	ops := map[string]int{}
	var negate *Mutation
	for i := range muts {
		ops[muts[i].Op]++
		if muts[i].Op == "negate-cond" && muts[i].Func == "Max" {
			negate = &muts[i]
		}
	}
	if ops["cmp-gt-to-ge"] == 0 {
		t.Errorf("expected a cmp-gt-to-ge mutation on Max, got ops=%v", ops)
	}
	if negate == nil {
		t.Fatalf("expected a negate-cond mutation inside Max, got ops=%v", ops)
	}
	if negate.New != "!(a > b)" {
		t.Errorf("negate-cond New = %q, want %q", negate.New, "!(a > b)")
	}
}

// findNegateCond returns the negate-cond mutation inside Max, failing the test
// if it is absent.
func findNegateCond(t *testing.T, root string) Mutation {
	t.Helper()
	muts, err := collectMutations(root, root, nil)
	if err != nil {
		t.Fatalf("collectMutations: %v", err)
	}
	for _, m := range muts {
		if m.Op == "negate-cond" && m.Func == "Max" {
			return m
		}
	}
	t.Fatal("no negate-cond mutation found in toy fixture")
	return Mutation{}
}

// TestOracleHealth_RedProof is the tool's own red/green proof. The same
// behaviour-changing mutant (Max -> min) must SURVIVE the weak oracle and be
// KILLED by the strong one. If oraclehealth reported both as killed it would be
// claiming an oracle hole does not exist when it does; if it reported both as
// survived it would be unable to detect any oracle at all. Only the asymmetry
// below proves the tool measures what it claims.
func TestOracleHealth_RedProof(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping fuzzing integration proof in -short mode")
	}
	root := toyModuleCopy(t)
	m := findNegateCond(t, root)

	env := Env{
		ModuleRoot: root,
		PkgRel:     "",
		FuzzTime:   3 * time.Second,
		Parallel:   1,
		Nice:       10,
		GOMAXPROCS: 2,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	// Sanity: both targets must be green on the unmutated fixture, otherwise a
	// "kill" would be meaningless.
	for _, target := range []string{"FuzzWeak", "FuzzStrong"} {
		if ok, detail := env.baselineGreen(ctx, target); !ok {
			t.Fatalf("baseline not green for %s:\n%s", target, detail)
		}
	}

	strong := applyAndRun(ctx, env, "FuzzStrong", m)
	if strong.Verdict != Killed {
		t.Errorf("strong oracle: verdict = %s, want KILLED\ndetail:\n%s", strong.Verdict, strong.Detail)
	}

	weak := applyAndRun(ctx, env, "FuzzWeak", m)
	if weak.Verdict != Survived {
		t.Errorf("weak oracle: verdict = %s, want SURVIVED\ndetail:\n%s", weak.Verdict, weak.Detail)
	}
}
