// depmatrix_test.go — tests for the dependency gap guard.
//
// The matrix is generated on demand and not committed (see gaps.go), so there
// is no staleness test. What is checked instead:
//
//   - TestDepFuzzGaps_EveryOpenGapIsExempt: every REACH=UNTRUSTED, FUZZ=NONE
//     dependency in the live derivation has a fragment under docs/fuzz/dep-fuzz.d.
//   - TestDepFuzzGaps_NoStaleOrDuplicateExemption: every fragment names a
//     dependency that is still an open gap, and no module has two fragments.
//   - TestDepFuzzGapExemptionsNotExpired: the dates parse (and, in the nightly
//     run, have not passed), through guardrules.CheckExpiry; no test reads the
//     clock.
//   - TestCheckGaps_Calibration and TestCheckGaps_IgnoresVersionAndImportCount:
//     the comparison fires on planted violations and stays green on a known-good
//     case, on synthetic rows, so they do not depend on the repository.
//   - TestParseGapExemption: the fragment parser.
//   - TestDepFuzzMatrix_GoModAddGoesRed: a new direct require line is parsed.
//
// The two live guards walk every go.mod and .go file, so they report through
// guardrules.Rollout (docs/guard-rollout.d rows) until promoted.
//
// WHAT THESE TESTS DO NOT VERIFY:
//   - That fuzz targets compile or exercise the dependency correctly.
//   - That REACH/FUZZ classifications are semantically accurate.
//   - Indirect dependencies (only direct requires are tracked).
//   - That an exemption's reason is true.
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/guardrules"
)

// findRepoRootForTest walks up from the package directory to the repo root.
func findRepoRootForTest(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("cannot determine cwd: %v", err)
	}
	for {
		if goModModulePath(filepath.Join(dir, "go.mod")) == "github.com/keyorixhq/keyorix" {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("cannot find repo root (no go.mod with module github.com/keyorixhq/keyorix found)")
		}
		dir = parent
	}
}

// liveGaps derives the matrix from the working tree and loads the fragments.
func liveGaps(t *testing.T) ([]DepRow, []gapExemption) {
	t.Helper()
	root := findRepoRootForTest(t)
	rows, _, err := generate(root)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	ex, err := loadGapExemptions(root)
	if err != nil {
		t.Fatalf("load exemptions: %v", err)
	}
	return rows, ex
}

func TestDepFuzzGaps_EveryOpenGapIsExempt(t *testing.T) {
	g := guardrules.Rollout(t)
	rows, ex := liveGaps(t)
	for _, m := range checkGaps(rows, ex).Unexempted {
		g.Errorf("%s is reachable from untrusted input and has no fuzz target. "+
			"Add a fuzz target, or write %s/%s (module, expiry YYYY-MM-DD, reason; tab-separated)",
			m, gapDir, gapFileName(m))
	}
}

func TestDepFuzzGaps_NoStaleOrDuplicateExemption(t *testing.T) {
	g := guardrules.Rollout(t)
	rows, ex := liveGaps(t)
	f := checkGaps(rows, ex)
	for _, m := range f.Stale {
		g.Errorf("%s/%s exempts %s, which is not an untrusted-and-unfuzzed dependency any more "+
			"(fuzzed, no longer required, or no longer reachable); delete the fragment",
			gapDir, gapFileName(m), m)
	}
	for _, m := range f.Duplicate {
		g.Errorf("%s is exempted by more than one fragment", m)
	}
}

func TestDepFuzzGapExemptionsNotExpired(t *testing.T) {
	_, ex := liveGaps(t)
	for _, e := range ex {
		guardrules.CheckExpiry(t, guardrules.Expiry{
			Source:  e.Source,
			Key:     e.Module,
			Expires: e.Expires,
			Note:    e.Reason,
		})
	}
}

// row builds a synthetic matrix row for the calibration tests.
func row(module, reach, fuzz, version string, importCount int) DepRow {
	return DepRow{Module: module, Version: version, ImportCount: importCount, Reach: reach, Fuzz: fuzz}
}

func exempt(module string) gapExemption {
	return gapExemption{Module: module, Expires: "2099-01-01", Reason: "test", Source: gapDir + "/" + gapFileName(module)}
}

func TestCheckGaps_Calibration(t *testing.T) {
	const untrusted, none, direct = "UNTRUSTED", "NONE", "DIRECT"
	tests := []struct {
		name                         string
		rows                         []DepRow
		ex                           []gapExemption
		unexempted, stale, duplicate []string
	}{
		{name: "known-good: gap is exempt, fuzzed and tooling rows need nothing",
			rows: []DepRow{
				row("a/gap", untrusted, none, "v1", 1),
				row("b/fuzzed", untrusted, direct, "v1", 2),
				row("c/tooling", "TOOLING", none, "v1", 1),
			},
			ex: []gapExemption{exempt("a/gap")}},
		{name: "red: new untrusted unfuzzed dependency without a fragment",
			rows:       []DepRow{row("a/new", untrusted, none, "v1", 1)},
			unexempted: []string{"a/new"}},
		{name: "red: exemption left behind after the dependency got a fuzz target",
			rows:  []DepRow{row("a/gap", untrusted, direct, "v1", 1)},
			ex:    []gapExemption{exempt("a/gap")},
			stale: []string{"a/gap"}},
		{name: "red: exemption for a module that is gone",
			ex:    []gapExemption{exempt("a/removed")},
			stale: []string{"a/removed"}},
		{name: "red: two fragments for one module",
			rows:      []DepRow{row("a/gap", untrusted, none, "v1", 1)},
			ex:        []gapExemption{exempt("a/gap"), exempt("a/gap")},
			duplicate: []string{"a/gap"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := checkGaps(tc.rows, tc.ex)
			if strings.Join(got.Unexempted, ",") != strings.Join(tc.unexempted, ",") ||
				strings.Join(got.Stale, ",") != strings.Join(tc.stale, ",") ||
				strings.Join(got.Duplicate, ",") != strings.Join(tc.duplicate, ",") {
				t.Errorf("got %+v, want unexempted=%v stale=%v duplicate=%v", got, tc.unexempted, tc.stale, tc.duplicate)
			}
		})
	}
}

// TestCheckGaps_IgnoresVersionAndImportCount pins the property that made the
// old snapshot comparison fail every dependency-bump pull request: a different
// version or import count must not change the findings.
func TestCheckGaps_IgnoresVersionAndImportCount(t *testing.T) {
	before := []DepRow{row("a/gap", "UNTRUSTED", "NONE", "v1.0.0", 1), row("b/ok", "UNTRUSTED", "DIRECT", "v1.0.0", 1)}
	after := []DepRow{row("a/gap", "UNTRUSTED", "NONE", "v9.9.9", 40), row("b/ok", "UNTRUSTED", "DIRECT", "v2.0.0", 7)}
	ex := []gapExemption{exempt("a/gap")}
	if a, b := checkGaps(before, ex), checkGaps(after, ex); len(a.Unexempted)+len(a.Stale)+len(b.Unexempted)+len(b.Stale) != 0 {
		t.Errorf("version or import-count change altered the findings: before=%+v after=%+v", a, b)
	}
}

func TestParseGapExemption(t *testing.T) {
	good := "# comment\nexample.com/m/v2\t2027-01-31\twhy\n"
	if e, err := parseGapExemption(gapFileName("example.com/m/v2"), []byte(good)); err != nil ||
		e.Module != "example.com/m/v2" || e.Expires != "2027-01-31" || e.Reason != "why" {
		t.Fatalf("good fragment: %+v, %v", e, err)
	}
	bad := map[string]string{
		"no row":          "# only a comment\n",
		"two rows":        "a\t2027-01-01\tr\nb\t2027-01-01\tr\n",
		"two fields":      "a\t2027-01-01\n",
		"empty reason":    "a\t2027-01-01\t \n",
		"wrong file name": "other\t2027-01-01\tr\n",
	}
	for name, content := range bad {
		if _, err := parseGapExemption(gapFileName("a"), []byte(content)); err == nil {
			t.Errorf("%s: parsed without error", name)
		}
	}
}

// TestDepFuzzMatrix_GoModAddGoesRed proves a new direct require line is parsed,
// which is the input the gap guard depends on.
func TestDepFuzzMatrix_GoModAddGoesRed(t *testing.T) {
	root := findRepoRootForTest(t)
	const fakeModule = "example.com/fake-dep-goesred"
	const fakeLine = "\trequire example.com/fake-dep-goesred v0.0.0-00010101000000-000000000000\n"

	rowsClean, _, err := generate(root)
	if err != nil {
		t.Fatalf("generate (clean): %v", err)
	}
	for _, r := range rowsClean {
		if r.Module == fakeModule {
			t.Fatalf("green proof failed: %q found in the clean matrix", fakeModule)
		}
	}
	origData, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	found := false
	for _, d := range parseGoModDirect(string(origData)+fakeLine, "go.mod") {
		if d.Module == fakeModule {
			found = true
		}
	}
	if !found {
		t.Errorf("red proof failed: %q not detected in patched go.mod content", fakeModule)
	}
}
