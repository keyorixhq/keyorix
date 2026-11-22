package ci_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const weightsFile = "scripts/ci-test-weights.tsv"

// TestWeightsFileNamesExistingTests fails when a row of scripts/ci-test-weights.tsv
// names a top-level test that no *_test.go file of its package declares (#4626:
// #4590 renamed TestSlowDiskSync_HoldsReadLockAcrossSync and the row kept its
// old name). A stale row never breaks the split (every test lands in exactly one
// shard whatever the weights say) but it silently mis-balances it: the renamed
// test is weighed as an average test and the dead name weighs nothing.
//
// Recognised forms: a top-level `func TestX(`, `func FuzzX(` or `func BenchmarkX(`
// in a *_test.go file directly inside the row's package directory. Subtests
// (names with "/") are never listed (gen-test-weights.py drops them). The `*`
// default row has no test name and is skipped.
func TestWeightsFileNamesExistingTests(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, weightsFile))
	if err != nil {
		t.Fatal(err)
	}
	decl := regexp.MustCompile(`(?m)^func ((?:Test|Fuzz|Benchmark)\w*)\(`)
	declared := map[string]map[string]bool{} // package dir -> declared test names
	load := func(pkg string) map[string]bool {
		if names, ok := declared[pkg]; ok {
			return names
		}
		names := map[string]bool{}
		files, _ := filepath.Glob(filepath.Join(root, filepath.FromSlash(pkg), "*_test.go"))
		for _, f := range files {
			src, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range decl.FindAllSubmatch(src, -1) {
				names[string(m[1])] = true
			}
		}
		declared[pkg] = names
		return names
	}

	rows := 0
	for i, line := range strings.Split(string(raw), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 3 {
			t.Errorf("%s:%d: want <package>\\t<test>\\t<weight>, got %q", weightsFile, i+1, line)
			continue
		}
		pkg, test := f[0], f[1]
		if test == "*" {
			continue
		}
		rows++
		if !load(pkg)[test] {
			t.Errorf("%s:%d: %s names %s, which no *_test.go in that package declares; "+
				"regenerate or fix the row (gen-test-weights.py)", weightsFile, i+1, pkg, test)
		}
	}
	if rows == 0 {
		t.Fatal(weightsFile + " has no per-test rows: the check would pass vacuously")
	}
}
