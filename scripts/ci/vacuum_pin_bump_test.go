package ci_test

import (
	"os/exec"
	"path/filepath"
	"testing"
)

// TestVacuumPinBumpUnit runs vacuum_pin_bump_unittest.py: vacuum-pin-bump.py
// against the real v0.42.3 release data (the repo pin must be "already current")
// and against a derived newer release (rewrite, 7-day cooldown boundary, draft,
// prerelease, downgrade, missing platform, checksum/digest disagreement, bad
// pin). No network.
func TestVacuumPinBumpUnit(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not on PATH")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("python3", "scripts/ci/vacuum_pin_bump_unittest.py")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("vacuum_pin_bump_unittest.py: %v\n%s", err, out)
	}
}
