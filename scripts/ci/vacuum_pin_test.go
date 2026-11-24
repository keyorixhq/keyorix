package ci_test

import (
	"os/exec"
	"testing"
)

// TestVacuumInstallerRefusalSelfTestGuard runs vacuum-install-selftest.sh, the
// offline calibration of devtools/vacuum/install.sh: green on a good download
// and on a good cache entry, a corrupted cache entry is deleted and downloaded
// once more, and every refusal path (wrong hash, a fresh download that also
// mismatches, a pin without a line for this os/arch, a duplicate key,
// whitespace or quotes in a pin line, an unknown key, a binary reporting
// another version) exits 1 and leaves nothing installed. No network: the
// release is a file:// directory. It does not test the live release: that is
// the openapi-lint job's own download.
func TestVacuumInstallerRefusalSelfTestGuard(t *testing.T) {
	for _, tool := range []string{"bash", "tar", "curl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed", tool)
		}
	}
	out, err := exec.Command("bash", "vacuum-install-selftest.sh").CombinedOutput()
	if err != nil {
		t.Fatalf("vacuum-install-selftest.sh: %v\n%s", err, out)
	}
	t.Logf("%s", out)
}
