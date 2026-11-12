package ci_test

import (
	"os/exec"
	"path/filepath"
	"testing"
)

// Runs scripts/ci/weights_drift_unittest.py, the tests of
// scripts/ci/check-weights-drift.py and logs-to-timings.py (WEIGHTS-DRIFT-1):
// calibration against the verbose runs 42522635702 (old weights file: the check
// must fire) and 42586426128 (current file: it must not report a drift), the two
// rules at their edges, the converter and the report-only exit status. The check
// is report-only and wired into no workflow; nothing here changes what CI runs.
func TestWeightsDriftUnit(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not on PATH")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("python3", "scripts/ci/weights_drift_unittest.py")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("weights_drift_unittest.py: %v\n%s", err, out)
	}
}
