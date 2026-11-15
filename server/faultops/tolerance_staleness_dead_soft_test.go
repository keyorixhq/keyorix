package faultops

import (
	"fmt"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/guardrules"
)

// stalenessRecTB records what reportToleranceStaleness reports instead of
// failing the real test.
type stalenessRecTB struct {
	testing.TB
	errs, logs []string
}

func (r *stalenessRecTB) Errorf(f string, a ...any) { r.errs = append(r.errs, fmt.Sprintf(f, a...)) }
func (r *stalenessRecTB) Logf(f string, a ...any)   { r.logs = append(r.logs, fmt.Sprintf(f, a...)) }

// TestToleranceStaleness_DeadIsSoftInQueueHardOnMain proves the item-4b contract
// of FLAKE-ROOT-NOV-3 on synthetic classifications: a dead tolerance (its fault
// fired, the oracle no longer reports it: what a PR fixing the pinned bug causes)
// is only logged in a pull_request / merge_group run and fails under
// KEYORIX_GUARD_ROLLOUT=enforce (main push, nightly); an inconclusive, undrivable
// or ratchet verdict fails in both modes.
func TestToleranceStaleness_DeadIsSoftInQueueHardOnMain(t *testing.T) {
	dead := toleranceStaleness{dead: []string{"REST POST /x/GetFoo/error#1"}}

	t.Setenv(guardrules.EnvRollout, "")
	r := &stalenessRecTB{TB: t}
	reportToleranceStaleness(r, dead)
	if len(r.errs) != 0 {
		t.Fatalf("a dead tolerance must not fail a queue run, got %v", r.errs)
	}
	if len(r.logs) != 1 || !strings.Contains(r.logs[0], "FINDING CLOSED: knownOpenTolerances") ||
		!strings.Contains(r.logs[0], "REST POST /x/GetFoo/error#1") {
		t.Fatalf("a dead tolerance must be named in the log, got %v", r.logs)
	}

	t.Setenv(guardrules.EnvRollout, "enforce")
	r = &stalenessRecTB{TB: t}
	reportToleranceStaleness(r, dead)
	if len(r.errs) != 1 || !strings.Contains(r.errs[0], "FINDING CLOSED") {
		t.Fatalf("a dead tolerance must fail under %s=enforce, got errs=%v logs=%v", guardrules.EnvRollout, r.errs, r.logs)
	}

	hard := map[string]toleranceStaleness{
		"inconclusive": {inconclusive: []string{"REST POST /x/GetFoo/error#1 (reference run failed)"}},
		"undrivable":   {undrivable: []string{"REST POST /x/GetFoo/error#1 (not fired)"}},
		"revivedLive":  {revivedLive: []string{"REST POST /x/GetFoo/error#1"}},
	}
	for name, c := range hard {
		for _, mode := range []string{"", "enforce"} {
			t.Setenv(guardrules.EnvRollout, mode)
			r := &stalenessRecTB{TB: t}
			reportToleranceStaleness(r, c)
			if len(r.errs) != 1 {
				t.Errorf("%s must fail with %s=%q, got errs=%v logs=%v", name, guardrules.EnvRollout, mode, r.errs, r.logs)
			}
		}
	}
}
