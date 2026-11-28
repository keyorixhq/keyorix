package lib

import (
	"os/exec"
	"testing"
)

// TestAirgapE2EScript runs airgap-e2e_test.sh (#4700): scripts/airgap-e2e.sh against a fake
// container engine must start every container as the caller's uid:gid and print the
// container's logs when the server never becomes healthy. The real run needs Docker and is
// a manual `make airgap-e2e`.
func TestAirgapE2EScript(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq not installed: airgap-e2e.sh requires it")
	}
	out, err := exec.Command("bash", "airgap-e2e_test.sh").CombinedOutput() // #nosec G204 -- fixed in-repo script
	if err != nil {
		t.Fatalf("airgap-e2e_test.sh failed: %v\n%s", err, out)
	}
	t.Logf("%s", out)
}
