package ci_test

import (
	"os/exec"
	"path/filepath"
	"testing"
)

// Runs scripts/ci/coverage_shadow_unittest.py, the unit tests of
// scripts/ci/coverage-shadow.py (CI-SELECT-2, lever C in shadow mode): the
// diff-vs-coverage-profile matcher, the temp-file cleanup on every exit path
// and the "every doubt is KEEP" rules. The script is logging-only; nothing
// here changes which tests CI runs.
func TestCoverageShadowUnit(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not on PATH")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("python3", "scripts/ci/coverage_shadow_unittest.py")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("coverage_shadow_unittest.py: %v\n%s", err, out)
	}
}
