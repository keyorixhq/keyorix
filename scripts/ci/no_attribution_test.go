package ci_test

import (
	"os/exec"
	"testing"
)

// TestNoAttributionCheckScript runs check-no-attribution-test.sh, the offline
// tests of check-no-attribution.sh (the no-attribution workflow's check) and
// .githooks/commit-msg, so the Go suite fails when either stops rejecting an
// attribution pattern or starts rejecting the rule text in CLAUDE.md,
// web/CLAUDE.md or docs/adr-081-github-flow-branching.md. The workflow job
// also runs the script on every PR, whatever the PR touches.
func TestNoAttributionCheckScript(t *testing.T) {
	for _, tool := range []string{"bash", "git"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed", tool)
		}
	}
	out, err := exec.Command("bash", "check-no-attribution-test.sh").CombinedOutput()
	if err != nil {
		t.Fatalf("check-no-attribution-test.sh: %v\n%s", err, out)
	}
	t.Logf("%s", out)
}
