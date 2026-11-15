package guardrules

import (
	"os"
	"testing"
)

// KnownFindingClosed is what a test that pins "bug X still exists" calls when
// it finds X fixed. Such a test goes red the moment ANY PR fixes the bug, so it
// ejected the unrelated PR queued next to the fixer from the merge queue
// (#4100, #4115, #4023, #4038). On pull_request and merge_group runs it only
// logs a "FINDING CLOSED" line; on main pushes and the nightly run
// (KEYORIX_GUARD_ROLLOUT=enforce, see Rollout) it fails, so the stale entry
// still gets removed instead of rotting.
//
// It changes nothing while the bug is still present: the caller keeps asserting
// the pinned behaviour and only the "it is fixed" branch calls this.
func KnownFindingClosed(t testing.TB, id, detail string) {
	t.Helper()
	if os.Getenv(EnvRollout) == "enforce" {
		t.Errorf("FINDING CLOSED: %s: %s: remove it from the known list", id, detail)
		return
	}
	t.Logf("FINDING CLOSED: %s: %s: remove it from the known list (blocking on main and nightly, %s=enforce)", id, detail, EnvRollout)
}
