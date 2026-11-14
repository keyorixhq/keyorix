package guardrules

import (
	"strings"
	"testing"
)

// TestKnownFindingClosed_LogsInQueueAndFailsOnMain proves both directions: a
// closed finding must not fail a pull_request / merge_group run, and must fail
// where KEYORIX_GUARD_ROLLOUT=enforce (main push, nightly).
func TestKnownFindingClosed_LogsInQueueAndFailsOnMain(t *testing.T) {
	t.Setenv(EnvRollout, "")
	r := &recTB{TB: t}
	KnownFindingClosed(r, "iface-X", "no longer differs")
	if len(r.errs) != 0 {
		t.Fatalf("a closed finding must not fail a queue run, got %v", r.errs)
	}
	if len(r.logs) != 1 || !strings.Contains(r.logs[0], "FINDING CLOSED: iface-X: no longer differs") {
		t.Fatalf("a closed finding must say so in the log, got %v", r.logs)
	}

	t.Setenv(EnvRollout, "enforce")
	r = &recTB{TB: t}
	KnownFindingClosed(r, "iface-X", "no longer differs")
	if len(r.errs) != 1 || !strings.Contains(r.errs[0], "remove it from the known list") {
		t.Fatalf("a closed finding must fail under %s=enforce, got errs=%v logs=%v", EnvRollout, r.errs, r.logs)
	}
}
