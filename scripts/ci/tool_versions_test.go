package ci_test

import (
	"os/exec"
	"testing"

	"github.com/keyorixhq/keyorix/internal/guardrules"
)

// TestToolVersionsCheckScript runs check-tool-versions-test.sh, the offline
// calibration of check-tool-versions.sh: green on an untouched copy of the
// workflows, red on every drift shape the script claims to catch (a KEY:
// entry, an inline go install / release URL / image pin, a missing semgrep
// digest, a listed tool no longer pinned, a pin through another variable),
// and exit 2 on an env file or KEY: entry it cannot parse. It fails the Go
// suite when the script's logic regresses, whatever the tree's pins are.
func TestToolVersionsCheckScript(t *testing.T) {
	for _, tool := range []string{"bash", "awk", "sed"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed", tool)
		}
	}
	out, err := exec.Command("bash", "check-tool-versions-test.sh").CombinedOutput()
	if err != nil {
		t.Fatalf("check-tool-versions-test.sh: %v\n%s", err, out)
	}
	t.Logf("%s", out)
}

// TestToolVersionsGuard runs check-tool-versions.sh on the repository: every
// tool version a workflow pins must equal scripts/ci/tool-versions.env, and
// every tool listed there must still be pinned somewhere. It sees only the
// pin shapes listed in the script header; a pin written another way is not
// checked (the self-test above proves the listed shapes are).
func TestToolVersionsGuard(t *testing.T) {
	g := guardrules.Rollout(t)
	for _, tool := range []string{"bash", "awk", "find"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed", tool)
		}
	}
	out, err := exec.Command("bash", "check-tool-versions.sh").CombinedOutput()
	if err != nil {
		g.Fatalf("check-tool-versions.sh: %v\n%s\nTo bump a tool, change scripts/ci/tool-versions.env and the workflow pin in the same PR.", err, out)
	}
	t.Logf("%s", out)
}
